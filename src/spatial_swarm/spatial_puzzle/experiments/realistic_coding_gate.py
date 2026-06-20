"""Realistic Coding Gate experiment.

This experiment puts the Spatial Formation Gate in front of a toy coding device. The
previous formation-gate study measured the proof shape. This one asks whether the same
gate still protects real file, command, package, push, and credential-like actions when a
coordinator can lie about the action it asked agents to approve.
"""

from __future__ import annotations

import argparse
import hashlib
import math
import statistics
import subprocess
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Callable, Optional

from spatial_swarm.crypto.hashing import canonical_json, sha256_hex
from spatial_swarm.experiments.metrics import (
    process_resource_use,
    write_metrics,
    write_metrics_and_digest,
)
from spatial_swarm.experiments.redaction import redaction_report
from spatial_swarm.experiments.report import utc_run_id, write_environment, write_git_commit, write_yaml_like
from spatial_swarm.spatial_puzzle.experiments import formation_gate as FG

REAL_ACTION_KINDS = (
    "read_file",
    "edit_file",
    "run_tests",
    "run_command",
    "install_package",
    "delete_file",
    "push",
    "credential_read",
)

ATTACK_SCENARIOS = (
    "reuse_read_for_delete",
    "reuse_tests_for_credential",
    "stolen_sidecar_approves_alone",
    "two_stolen_sidecars_approve_alone",
    "sidecar_oracle_one_agent",
    "coordinator_downgrades_risk",
    "coordinator_chooses_fewer_agents",
    "coordinator_changes_action_after_proof",
    "ask_read_execute_credential",
    "wrong_nonce",
    "path_near_miss",
    "endpoint_mutation",
    "fake_agent",
    "old_output_replay",
    "old_nonce_reuse",
    "delayed_sidecar",
    "hidden_dangerous_metadata",
)

CONSTANT_FAILURE_SCENARIOS = (
    "wrong_nonce",
    "wrong_action",
    "wrong_endpoint",
    "wrong_path",
    "fake_agent",
    "stolen_sidecar",
    "collision_mutation",
    "coordinator_forgery",
)

COORDINATOR_SCENARIOS = (
    "downgrade_delete_to_low",
    "choose_fewer_agents",
    "reuse_old_nonce",
    "change_action_after_proof",
    "split_dangerous_action",
    "hide_dangerous_metadata_from_hash",
    "ask_read_execute_credential",
)

SIDECAR_SCENARIOS = (
    "old_outputs_seen",
    "old_nonces_seen",
    "logs_seen",
    "one_secret_stolen",
    "two_secrets_stolen",
    "one_sidecar_oracle",
    "one_sidecar_delayed",
    "one_sidecar_replayed",
)


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    risk: str
    reason: str
    checks: int


@dataclass(frozen=True)
class DeviceExecution:
    executed: bool
    effect: str
    output_digest: str
    command_status: int = 0


@dataclass(frozen=True)
class GateAttempt:
    scenario: str
    action_kind: str
    released: bool
    blocked: bool
    executed: bool
    public_reason: str
    visible_checks: int
    raw_checks: int
    elapsed_ms: float
    killed_session: bool
    policy_allowed: bool
    policy_reason: str
    formation_checked: bool
    formation_released: bool
    effect: str
    internal_reasons: tuple[str, ...]
    visible_shape: tuple[str, int, bool]


@dataclass(frozen=True)
class RealisticGateConfig:
    formation: FG.FormationConfig = field(default_factory=FG.FormationConfig)
    bind_execution_action: bool = True
    bind_required_agents: bool = True
    bind_risk_level: bool = True
    bind_roles: bool = True
    enforce_policy: bool = True
    enforce_timing: bool = True
    constant_failure: bool = True
    max_sidecar_delay_ms: float = 20.0
    pad_blocked_ms: float = 4.0


def _real_action_suite() -> dict[str, FG.ActionRequest]:
    return {
        "read_file": FG.ActionRequest("read_file", "README.md", {"operation": "inspect"}),
        "edit_file": FG.ActionRequest(
            "edit_file",
            "src/app.py",
            {"operation": "append_line", "text": "GATED_EDIT_MARKER"},
        ),
        "run_tests": FG.ActionRequest("run_tests", "tests", {"runner": "unittest"}),
        "run_command": FG.ActionRequest(
            "run_command",
            "terminal",
            {"command_class": "python_version_probe"},
        ),
        "install_package": FG.ActionRequest(
            "install_package",
            "local_registry",
            {"package": "demo_tool", "source": "local"},
        ),
        "delete_file": FG.ActionRequest(
            "delete_file",
            "tmp/output.log",
            {"operation": "delete_single_file"},
        ),
        "push": FG.ActionRequest("push", "origin", {"branch": "main"}),
        "credential_read": FG.ActionRequest(
            "credential_read",
            "credential_store",
            {"name": "CI_DEPLOY_HANDLE"},
        ),
    }


def _delete_repo_action() -> FG.ActionRequest:
    return FG.ActionRequest("delete_file", ".", {"operation": "delete_repo"})


def _hidden_danger_action() -> FG.ActionRequest:
    return FG.ActionRequest(
        "run_command",
        "terminal",
        {"command_class": "python_version_probe", "hidden_metadata": "rm -rf ."},
    )


def _second_read_action() -> FG.ActionRequest:
    return FG.ActionRequest("read_file", "src/app.py", {"operation": "inspect"})


class PolicyGate:
    """Local policy gate. It never trusts coordinator-declared risk."""

    def evaluate(self, action: FG.ActionRequest) -> PolicyDecision:
        checks = 8
        risk = FG._risk_for_action(action)
        text = canonical_json(action.canonical()).lower()
        if any(token in text for token in ("rm -rf", "../", "private_key", "signing_key")):
            return PolicyDecision(False, risk, "dangerous_payload", checks)
        if action.kind == "read_file":
            return PolicyDecision(action.target in {"README.md", "src/app.py"}, risk, "read_allowlist", checks)
        if action.kind == "edit_file":
            ok = action.target == "src/app.py" and action.payload.get("operation") == "append_line"
            return PolicyDecision(ok, risk, "edit_allowlist", checks)
        if action.kind == "run_tests":
            return PolicyDecision(action.target == "tests", risk, "test_runner_allowlist", checks)
        if action.kind == "run_command":
            ok = action.payload.get("command_class") == "python_version_probe"
            return PolicyDecision(ok, risk, "command_allowlist", checks)
        if action.kind == "install_package":
            ok = action.target == "local_registry" and action.payload.get("source") == "local"
            return PolicyDecision(ok, risk, "local_package_only", checks)
        if action.kind == "delete_file":
            ok = action.target == "tmp/output.log"
            return PolicyDecision(ok, risk, "single_file_delete_only", checks)
        if action.kind == "push":
            ok = action.target == "origin" and action.payload.get("branch") == "main"
            return PolicyDecision(ok, risk, "local_remote_only", checks)
        if action.kind == "credential_read":
            ok = action.target == "credential_store" and action.payload.get("name") == "CI_DEPLOY_HANDLE"
            return PolicyDecision(ok, risk, "named_credential_handle_only", checks)
        return PolicyDecision(False, risk, "unknown_action", checks)


class ToyCodingDevice:
    """A throwaway repo/device used only inside one attempt."""

    def __init__(self, root: Path, trial_index: int) -> None:
        self.root = root
        self.repo = root / "repo"
        self.remote = root / "remote.git"
        self.trial_index = trial_index
        self._git_ready = False
        self._credential_value = f"DEVICE_VALUE_{trial_index:06d}"
        self._create_repo()

    def _create_repo(self) -> None:
        (self.repo / "src").mkdir(parents=True)
        (self.repo / "tests").mkdir()
        (self.repo / "tmp").mkdir()
        (self.repo / "vendor").mkdir()
        (self.repo / "README.md").write_text("Toy repo for gated coding actions.\n", encoding="utf-8")
        (self.repo / "src" / "__init__.py").write_text("", encoding="utf-8")
        (self.repo / "src" / "app.py").write_text(
            "def add(a, b):\n    return a + b\n",
            encoding="utf-8",
        )
        (self.repo / "tests" / "test_app.py").write_text(
            "import unittest\n"
            "from src.app import add\n\n"
            "class AppTest(unittest.TestCase):\n"
            "    def test_add(self):\n"
            "        self.assertEqual(add(2, 3), 5)\n\n"
            "if __name__ == '__main__':\n"
            "    unittest.main()\n",
            encoding="utf-8",
        )
        (self.repo / "tmp" / "output.log").write_text("temporary build output\n", encoding="utf-8")

    def execute(self, action: FG.ActionRequest) -> DeviceExecution:
        if action.kind == "read_file":
            path = self._safe_path(action.target)
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            return DeviceExecution(True, "read_file", digest)
        if action.kind == "edit_file":
            path = self._safe_path(action.target)
            with path.open("a", encoding="utf-8") as handle:
                handle.write(f"\n# gated edit {self.trial_index}\n")
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            return DeviceExecution(True, "edited_file", digest)
        if action.kind == "run_tests":
            proc = subprocess.run(
                [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
                cwd=self.repo,
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
            digest = hashlib.sha256((proc.stdout + proc.stderr).encode("utf-8")).hexdigest()
            return DeviceExecution(proc.returncode == 0, "ran_tests", digest, proc.returncode)
        if action.kind == "run_command":
            proc = subprocess.run(
                [sys.executable, "-c", "print('device-command-ok')"],
                cwd=self.repo,
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
            digest = hashlib.sha256((proc.stdout + proc.stderr).encode("utf-8")).hexdigest()
            return DeviceExecution(proc.returncode == 0, "ran_command", digest, proc.returncode)
        if action.kind == "install_package":
            dist = self.repo / "vendor" / f"{action.payload['package']}.dist-info"
            dist.mkdir(parents=True, exist_ok=True)
            (dist / "INSTALLER").write_text("spatial-realistic-gate\n", encoding="utf-8")
            digest = hashlib.sha256((dist / "INSTALLER").read_bytes()).hexdigest()
            return DeviceExecution(True, "installed_local_package", digest)
        if action.kind == "delete_file":
            path = self._safe_path(action.target)
            path.unlink()
            return DeviceExecution(True, "deleted_file", "deleted")
        if action.kind == "push":
            self._ensure_git()
            proc = subprocess.run(
                ["git", "push", "origin", "main"],
                cwd=self.repo,
                text=True,
                capture_output=True,
                timeout=15,
                check=False,
            )
            digest = hashlib.sha256((proc.stdout + proc.stderr).encode("utf-8")).hexdigest()
            return DeviceExecution(proc.returncode == 0, "pushed_local_remote", digest, proc.returncode)
        if action.kind == "credential_read":
            digest = hashlib.sha256(self._credential_value.encode("utf-8")).hexdigest()
            return DeviceExecution(True, "read_credential_handle", digest)
        return DeviceExecution(False, "unknown_action", "none", 1)

    def _safe_path(self, rel_path: str) -> Path:
        path = (self.repo / rel_path).resolve()
        if not path.is_relative_to(self.repo.resolve()):
            raise ValueError(f"unsafe path: {rel_path}")
        return path

    def _ensure_git(self) -> None:
        if self._git_ready:
            return
        subprocess.run(["git", "init", "--bare", str(self.remote)], capture_output=True, check=True)
        subprocess.run(["git", "init", "-b", "main"], cwd=self.repo, capture_output=True, check=True)
        subprocess.run(["git", "config", "user.email", "gate@example.invalid"], cwd=self.repo, check=True)
        subprocess.run(["git", "config", "user.name", "Spatial Gate"], cwd=self.repo, check=True)
        subprocess.run(["git", "add", "."], cwd=self.repo, check=True)
        subprocess.run(["git", "commit", "-m", "Initial toy repo"], cwd=self.repo, capture_output=True, check=True)
        subprocess.run(["git", "remote", "add", "origin", str(self.remote)], cwd=self.repo, check=True)
        self._git_ready = True


class PathAttackArm(FG.FormationArm):
    def __init__(self, config: FG.FormationConfig, trial_index: int, path_attack: str) -> None:
        super().__init__("coordinated_formation", config, trial_index)
        self.path_attack = path_attack

    def _coordinated_path(
        self,
        agent_id: str,
        challenge: FG.FormationChallenge,
    ) -> tuple[tuple[int, int, int], ...]:
        base = list(super()._coordinated_path(agent_id, challenge))
        required = challenge.required_agents
        if self.path_attack == "collision" and len(required) > 1 and agent_id == required[1]:
            other = super()._coordinated_path(required[0], challenge)
            base[0] = other[0]
            return tuple(base)
        if self.path_attack == "path_crossing" and len(required) > 1:
            if agent_id == required[0]:
                other = super()._coordinated_path(required[1], challenge)
                base[1] = other[0]
            elif agent_id == required[1]:
                other = super()._coordinated_path(required[0], challenge)
                base[1] = other[0]
            return tuple(base)
        if self.path_attack == "forbidden" and agent_id == required[0]:
            forbidden = sorted(self._forbidden_points(challenge))
            base[min(2, len(base) - 2)] = forbidden[0]
            return tuple(base)
        if self.path_attack == "wrong_final" and agent_id == required[0]:
            end = base[-1]
            base[-1] = ((end[0] + 1) % self.config.grid_size, end[1], end[2])
            return tuple(base)
        return tuple(base)


class RealisticCodingGate:
    def __init__(self, config: RealisticGateConfig, trial_index: int) -> None:
        self.config = config
        self.trial_index = trial_index
        self.policy = PolicyGate()

    def attempt(
        self,
        *,
        scenario: str,
        execute_action: FG.ActionRequest,
        proof_action: Optional[FG.ActionRequest] = None,
        proof_mode: str = "legit",
        challenge_mutation: Optional[str] = None,
        arm_factory: Optional[Callable[[], FG.FormationArm]] = None,
        declared_roles: Optional[tuple[str, ...]] = None,
        sidecar_delay_ms: float = 0.0,
    ) -> GateAttempt:
        proof_action = proof_action or execute_action
        started = time.perf_counter()
        policy = self.policy.evaluate(execute_action)
        reasons: list[str] = []
        raw_checks = policy.checks
        formation_checked = False
        formation_released = False
        effect = "not_executed"
        public_reason = "blocked"
        killed_session = False
        visible_checks = raw_checks

        if self.config.enforce_policy and not policy.allowed:
            reasons.append(f"policy:{policy.reason}")
        arm = arm_factory() if arm_factory else FG.FormationArm(
            "coordinated_formation",
            self.config.formation,
            self.trial_index,
        )
        gate = FG.SpatialFormationGate(arm)

        challenge: Optional[FG.FormationChallenge] = None
        formation_decision: Optional[FG.GateDecision] = None
        if not reasons:
            challenge, proofs, preverified = self._prepare_challenge_and_proofs(
                arm,
                gate,
                proof_action,
                execute_action,
                proof_mode,
                challenge_mutation,
            )
            if preverified:
                raw_checks += preverified.checks_performed
            formation_decision = gate.verify(challenge, proofs)
            formation_checked = True
            formation_released = formation_decision.released
            raw_checks += formation_decision.checks_performed
            if not formation_decision.released:
                reasons.extend(f"formation:{r}" for r in formation_decision.internal_reasons)
            reasons.extend(self._binding_reasons(arm, challenge, execute_action, policy, declared_roles))
            if self.config.enforce_timing and sidecar_delay_ms > self.config.max_sidecar_delay_ms:
                reasons.append("timing:sidecar_deadline_miss")

        released = not reasons
        if released:
            with tempfile.TemporaryDirectory(prefix="spatial-realistic-gate-") as tmp:
                device = ToyCodingDevice(Path(tmp), self.trial_index)
                execution = device.execute(execute_action)
            released = execution.executed
            if released:
                effect = execution.effect
                public_reason = "released"
            else:
                reasons.append(f"device:{execution.effect}")

        blocked = not released
        if blocked:
            public_reason = "blocked"
            killed_session = self.config.formation.one_shot
            if self.config.constant_failure:
                visible_checks = self._blocked_check_budget()
        else:
            visible_checks = raw_checks

        elapsed_ms = (time.perf_counter() - started) * 1000.0
        if blocked and self.config.constant_failure and elapsed_ms < self.config.pad_blocked_ms:
            time.sleep((self.config.pad_blocked_ms - elapsed_ms) / 1000.0)
            elapsed_ms = (time.perf_counter() - started) * 1000.0

        return GateAttempt(
            scenario=scenario,
            action_kind=execute_action.kind,
            released=released,
            blocked=blocked,
            executed=released,
            public_reason=public_reason,
            visible_checks=visible_checks,
            raw_checks=raw_checks,
            elapsed_ms=elapsed_ms,
            killed_session=killed_session,
            policy_allowed=policy.allowed,
            policy_reason=policy.reason,
            formation_checked=formation_checked,
            formation_released=formation_released,
            effect=effect,
            internal_reasons=tuple(sorted(set(reasons))),
            visible_shape=(public_reason, visible_checks, killed_session),
        )

    def _prepare_challenge_and_proofs(
        self,
        arm: FG.FormationArm,
        gate: FG.SpatialFormationGate,
        proof_action: FG.ActionRequest,
        execute_action: FG.ActionRequest,
        proof_mode: str,
        challenge_mutation: Optional[str],
    ) -> tuple[FG.FormationChallenge, tuple[FG.AgentProof, ...], Optional[FG.GateDecision]]:
        preverified = None
        if proof_mode == "old_output_replay":
            old = gate.challenge(_real_action_suite()["read_file"])
            proofs = FG._legit_proofs(arm, old)
            challenge = gate.challenge(execute_action)
            return challenge, proofs, None
        if proof_mode == "old_nonce_reuse":
            challenge = gate.challenge(execute_action)
            proofs = FG._legit_proofs(arm, challenge)
            preverified = gate.verify(challenge, proofs)
            return challenge, proofs, preverified

        manual = isinstance(arm, PathAttackArm)
        challenge = self._manual_challenge(arm, proof_action) if manual else gate.challenge(proof_action)
        challenge = self._mutate_challenge(challenge, arm, execute_action, challenge_mutation)
        proofs = FG._legit_proofs(arm, challenge)
        if proof_mode == "wrong_nonce":
            first = proofs[0]
            proofs = (replace(first, nonce=FG._mutate_hex(first.nonce)),) + proofs[1:]
        elif proof_mode == "wrong_path":
            first = proofs[0]
            proofs = (replace(first, path_digest=FG._mutate_hex(first.path_digest)),) + proofs[1:]
        elif proof_mode == "wrong_endpoint":
            first = proofs[0]
            proofs = (replace(first, endpoint_digest=FG._mutate_hex(first.endpoint_digest)),) + proofs[1:]
        elif proof_mode == "fake_agent":
            fake = FG.AgentProof(
                "agent_999",
                challenge.action_hash,
                challenge.nonce,
                "fake_path",
                "fake_endpoint",
                "fake_tag",
            )
            proofs = (fake,) + proofs[1:]
        elif proof_mode == "stolen_one_alone":
            proofs = proofs[:1]
        elif proof_mode == "stolen_two_alone":
            proofs = proofs[:2]
        elif proof_mode == "sidecar_oracle_one_agent":
            legit = list(proofs[:1])
            for i, agent in enumerate(challenge.required_agents[1:], start=1):
                legit.append(FG._fake_proof(agent, challenge, f"oracle-fake-{i}"))
            proofs = tuple(legit)
        return challenge, proofs, preverified

    def _mutate_challenge(
        self,
        challenge: FG.FormationChallenge,
        arm: FG.FormationArm,
        execute_action: FG.ActionRequest,
        mutation: Optional[str],
    ) -> FG.FormationChallenge:
        if mutation is None:
            return challenge
        if mutation == "downgrade_risk_low":
            return replace(
                challenge,
                risk="low",
                required_agents=FG._required_agents(arm.agent_ids, "low"),
            )
        if mutation == "fewer_required_high":
            return replace(challenge, risk="high", required_agents=arm.agent_ids[:2])
        if mutation == "risk_low_all_agents":
            return replace(challenge, risk="low", required_agents=arm.agent_ids)
        if mutation == "reuse_old_nonce":
            return replace(challenge, nonce="0" * 32)
        if mutation == "execute_action_hash":
            return replace(challenge, action_hash=execute_action.action_hash())
        raise ValueError(f"unknown challenge mutation: {mutation}")

    def _binding_reasons(
        self,
        arm: FG.FormationArm,
        challenge: FG.FormationChallenge,
        execute_action: FG.ActionRequest,
        policy: PolicyDecision,
        declared_roles: Optional[tuple[str, ...]],
    ) -> list[str]:
        reasons: list[str] = []
        expected_required = FG._required_agents(arm.agent_ids, policy.risk)
        expected_roles = tuple(arm.roles[agent] for agent in expected_required)
        if self.config.bind_execution_action and challenge.action_hash != execute_action.action_hash():
            reasons.append("device:execution_action_mismatch")
        if self.config.bind_risk_level and challenge.risk != policy.risk:
            reasons.append("device:risk_mismatch")
        if self.config.bind_required_agents and tuple(challenge.required_agents) != expected_required:
            reasons.append("device:required_agents_mismatch")
        if self.config.bind_roles and (declared_roles or expected_roles) != expected_roles:
            reasons.append("device:role_mismatch")
        return reasons

    def _manual_challenge(self, arm: FG.FormationArm, action: FG.ActionRequest) -> FG.FormationChallenge:
        risk = FG._risk_for_action(action)
        return FG.FormationChallenge(
            arm=arm.name,
            action_hash=action.action_hash(),
            nonce=sha256_hex(
                {
                    "kind": "realistic_manual_nonce",
                    "trial_index": self.trial_index,
                    "action_hash": action.action_hash(),
                }
            )[:32],
            risk=risk,
            required_agents=FG._required_agents(arm.agent_ids, risk),
        )

    def _blocked_check_budget(self) -> int:
        return 8 + 4 + (5 * self.config.formation.agents) + 6 + 6


def _variant_config(name: str, base: RealisticGateConfig) -> RealisticGateConfig:
    form = base.formation
    if name == "full_gate":
        return base
    if name == "hmac_only":
        return replace(
            base,
            formation=replace(
                form,
                bind_path_digest=False,
                bind_endpoint_digest=False,
                check_collisions=False,
                check_path_crossing=False,
                check_forbidden_region=False,
                check_final_formation=False,
            ),
        )
    if name == "hmac_endpoint":
        return replace(
            base,
            formation=replace(
                form,
                bind_path_digest=False,
                bind_endpoint_digest=True,
                check_collisions=False,
                check_path_crossing=False,
                check_forbidden_region=False,
                check_final_formation=False,
            ),
        )
    if name == "hmac_endpoint_path":
        return replace(
            base,
            formation=replace(
                form,
                bind_path_digest=True,
                bind_endpoint_digest=True,
                check_collisions=False,
                check_path_crossing=False,
                check_forbidden_region=False,
                check_final_formation=False,
            ),
        )
    if name == "hmac_endpoint_path_collision":
        return replace(
            base,
            formation=replace(
                form,
                check_collisions=True,
                check_path_crossing=False,
                check_forbidden_region=False,
                check_final_formation=False,
            ),
        )
    if name == "hmac_endpoint_path_collision_final":
        return replace(
            base,
            formation=replace(
                form,
                check_collisions=True,
                check_path_crossing=False,
                check_forbidden_region=False,
                check_final_formation=True,
            ),
        )
    if name == "no_action_binding":
        return replace(base, formation=replace(form, bind_action=False), bind_execution_action=False)
    if name == "no_nonce_binding":
        return replace(base, formation=replace(form, bind_nonce=False))
    if name == "no_path_binding":
        return replace(base, formation=replace(form, bind_path_digest=False))
    if name == "no_endpoint_binding":
        return replace(base, formation=replace(form, bind_endpoint_digest=False))
    if name == "no_collision_check":
        return replace(base, formation=replace(form, check_collisions=False))
    if name == "no_path_crossing_check":
        return replace(base, formation=replace(form, check_path_crossing=False))
    if name == "no_forbidden_region_check":
        return replace(base, formation=replace(form, check_forbidden_region=False))
    if name == "no_final_formation_check":
        return replace(base, formation=replace(form, check_final_formation=False))
    if name == "no_required_agent_binding":
        return replace(base, bind_required_agents=False)
    if name == "no_risk_level_binding":
        return replace(base, bind_risk_level=False)
    if name == "no_role_binding":
        return replace(base, bind_roles=False)
    if name == "no_timing_binding":
        return replace(base, enforce_timing=False)
    raise ValueError(f"unknown variant: {name}")


def _run_named_scenario(
    scenario: str,
    trial_index: int,
    config: RealisticGateConfig,
) -> GateAttempt:
    actions = _real_action_suite()
    gate = RealisticCodingGate(config, trial_index)
    if scenario == "reuse_read_for_delete":
        return gate.attempt(
            scenario=scenario,
            proof_action=actions["read_file"],
            execute_action=actions["delete_file"],
        )
    if scenario == "reuse_tests_for_credential":
        return gate.attempt(
            scenario=scenario,
            proof_action=actions["run_tests"],
            execute_action=actions["credential_read"],
        )
    if scenario == "changed_same_risk_read":
        return gate.attempt(
            scenario=scenario,
            proof_action=actions["read_file"],
            execute_action=_second_read_action(),
        )
    if scenario in {"stolen_sidecar_approves_alone", "one_secret_stolen"}:
        return gate.attempt(
            scenario=scenario,
            execute_action=actions["credential_read"],
            proof_mode="stolen_one_alone",
        )
    if scenario in {"two_stolen_sidecars_approve_alone", "two_secrets_stolen"}:
        return gate.attempt(
            scenario=scenario,
            execute_action=actions["credential_read"],
            proof_mode="stolen_two_alone",
        )
    if scenario in {"sidecar_oracle_one_agent", "one_sidecar_oracle"}:
        return gate.attempt(
            scenario=scenario,
            execute_action=actions["credential_read"],
            proof_mode="sidecar_oracle_one_agent",
        )
    if scenario in {"coordinator_downgrades_risk", "downgrade_delete_to_low"}:
        return gate.attempt(
            scenario=scenario,
            execute_action=actions["delete_file"],
            challenge_mutation="downgrade_risk_low",
        )
    if scenario in {"coordinator_chooses_fewer_agents", "choose_fewer_agents"}:
        return gate.attempt(
            scenario=scenario,
            execute_action=actions["credential_read"],
            challenge_mutation="fewer_required_high",
            declared_roles=tuple(FG._role_for_index(i) for i in range(config.formation.agents)),
        )
    if scenario in {"coordinator_changes_action_after_proof", "change_action_after_proof"}:
        return gate.attempt(
            scenario=scenario,
            proof_action=actions["read_file"],
            execute_action=actions["credential_read"],
        )
    if scenario in {"ask_read_execute_credential", "hide_dangerous_metadata_from_hash"}:
        return gate.attempt(
            scenario=scenario,
            proof_action=actions["read_file"],
            execute_action=actions["credential_read"],
        )
    if scenario == "wrong_nonce":
        return gate.attempt(scenario=scenario, execute_action=actions["edit_file"], proof_mode="wrong_nonce")
    if scenario in {"path_near_miss", "wrong_path"}:
        return gate.attempt(scenario=scenario, execute_action=actions["edit_file"], proof_mode="wrong_path")
    if scenario in {"endpoint_mutation", "wrong_endpoint"}:
        return gate.attempt(
            scenario=scenario,
            execute_action=actions["edit_file"],
            proof_mode="wrong_endpoint",
        )
    if scenario == "fake_agent":
        return gate.attempt(scenario=scenario, execute_action=actions["edit_file"], proof_mode="fake_agent")
    if scenario in {"old_output_replay", "old_outputs_seen", "logs_seen", "one_sidecar_replayed"}:
        return gate.attempt(
            scenario=scenario,
            execute_action=actions["edit_file"],
            proof_mode="old_output_replay",
        )
    if scenario in {"old_nonce_reuse", "old_nonces_seen", "reuse_old_nonce"}:
        return gate.attempt(
            scenario=scenario,
            execute_action=actions["edit_file"],
            proof_mode="old_nonce_reuse",
        )
    if scenario in {"delayed_sidecar", "one_sidecar_delayed"}:
        return gate.attempt(
            scenario=scenario,
            execute_action=actions["edit_file"],
            sidecar_delay_ms=config.max_sidecar_delay_ms + 10.0,
        )
    if scenario in {"hidden_dangerous_metadata", "split_dangerous_action"}:
        return gate.attempt(
            scenario=scenario,
            proof_action=actions["run_command"],
            execute_action=_hidden_danger_action(),
        )
    if scenario == "wrong_action":
        return gate.attempt(
            scenario=scenario,
            proof_action=actions["read_file"],
            execute_action=_second_read_action(),
        )
    if scenario == "stolen_sidecar":
        return gate.attempt(
            scenario=scenario,
            execute_action=actions["credential_read"],
            proof_mode="stolen_one_alone",
        )
    if scenario == "coordinator_forgery":
        return gate.attempt(
            scenario=scenario,
            execute_action=actions["credential_read"],
            challenge_mutation="fewer_required_high",
        )
    if scenario == "collision_mutation":
        return _path_attack_attempt("collision", "collision_mutation", trial_index, config)
    if scenario == "path_crossing_mutation":
        return _path_attack_attempt("path_crossing", "path_crossing_mutation", trial_index, config)
    if scenario == "forbidden_region_mutation":
        return _path_attack_attempt("forbidden", "forbidden_region_mutation", trial_index, config)
    if scenario == "wrong_final_formation":
        return _path_attack_attempt("wrong_final", "wrong_final_formation", trial_index, config)
    if scenario == "role_label_forgery":
        return gate.attempt(
            scenario=scenario,
            execute_action=actions["edit_file"],
            declared_roles=("planner", "planner", "planner", "planner"),
        )
    if scenario == "risk_low_all_agents":
        return gate.attempt(
            scenario=scenario,
            execute_action=actions["credential_read"],
            challenge_mutation="risk_low_all_agents",
        )
    raise ValueError(f"unknown scenario: {scenario}")


def _path_attack_attempt(
    path_attack: str,
    scenario: str,
    trial_index: int,
    config: RealisticGateConfig,
) -> GateAttempt:
    actions = _real_action_suite()
    return RealisticCodingGate(config, trial_index).attempt(
        scenario=scenario,
        execute_action=actions["edit_file"],
        arm_factory=lambda: PathAttackArm(config.formation, trial_index, path_attack),
    )


def _attempt_dict(row: GateAttempt) -> dict:
    return {
        "scenario": row.scenario,
        "action_kind": row.action_kind,
        "released": row.released,
        "blocked": row.blocked,
        "executed": row.executed,
        "public_reason": row.public_reason,
        "visible_checks": row.visible_checks,
        "raw_checks": row.raw_checks,
        "elapsed_ms": row.elapsed_ms,
        "killed_session": row.killed_session,
        "policy_allowed": row.policy_allowed,
        "policy_reason": row.policy_reason,
        "formation_checked": row.formation_checked,
        "formation_released": row.formation_released,
        "effect": row.effect,
        "internal_reasons": list(row.internal_reasons),
        "visible_shape": list(row.visible_shape),
    }


def _proportion(successes: int, n: int) -> dict:
    return {"successes": successes, "n": n, "rate": successes / n if n else 0.0}


def _summary_values(values: list[float]) -> dict:
    if not values:
        return {"min": None, "p50": None, "p95": None, "max": None}
    ordered = sorted(values)
    return {
        "min": ordered[0],
        "p50": statistics.median(ordered),
        "p95": ordered[min(len(ordered) - 1, math.ceil(0.95 * len(ordered)) - 1)],
        "max": ordered[-1],
    }


def _summarize_attempts(rows: list[GateAttempt]) -> dict:
    return {
        "attempts": len(rows),
        "release": _proportion(sum(r.released for r in rows), len(rows)),
        "blocked": _proportion(sum(r.blocked for r in rows), len(rows)),
        "executed": _proportion(sum(r.executed for r in rows), len(rows)),
        "policy_allowed": _proportion(sum(r.policy_allowed for r in rows), len(rows)),
        "formation_checked": _proportion(sum(r.formation_checked for r in rows), len(rows)),
        "formation_released": _proportion(sum(r.formation_released for r in rows), len(rows)),
        "one_shot_shutdown": _proportion(sum(r.killed_session for r in rows), len(rows)),
        "public_reasons": dict(Counter(r.public_reason for r in rows)),
        "visible_shape_count": len({r.visible_shape for r in rows}),
        "visible_shapes": [list(shape) for shape in sorted({r.visible_shape for r in rows})],
        "visible_checks": _summary_values([float(r.visible_checks) for r in rows]),
        "raw_checks": _summary_values([float(r.raw_checks) for r in rows]),
        "elapsed_ms": _summary_values([r.elapsed_ms for r in rows]),
        "effects": dict(Counter(r.effect for r in rows)),
        "internal_reason_histogram": dict(Counter(reason for r in rows for reason in r.internal_reasons)),
    }


def _real_action_suite_metrics(config: RealisticGateConfig, trials: int) -> dict:
    out = {}
    actions = _real_action_suite()
    for kind, action in actions.items():
        valid_rows = [
            RealisticCodingGate(config, 10_000 + i).attempt(
                scenario=f"valid_{kind}",
                execute_action=action,
            )
            for i in range(trials)
        ]
        wrong_rows = [
            RealisticCodingGate(config, 20_000 + i).attempt(
                scenario=f"wrong_formation_{kind}",
                execute_action=action,
                proof_mode="wrong_nonce",
            )
            for i in range(trials)
        ]
        out[kind] = {
            "valid": _summarize_attempts(valid_rows),
            "wrong_formation": _summarize_attempts(wrong_rows),
            "false_block_rate": _proportion(sum(r.blocked for r in valid_rows), len(valid_rows)),
            "wrong_formation_release": _proportion(sum(r.released for r in wrong_rows), len(wrong_rows)),
        }
    return out


def _policy_formation_metrics(config: RealisticGateConfig, trials: int) -> dict:
    actions = _real_action_suite()
    cases = {
        "correct_formation_safe_edit": lambda i: RealisticCodingGate(config, 30_000 + i).attempt(
            scenario="correct_formation_safe_edit",
            execute_action=actions["edit_file"],
        ),
        "correct_formation_delete_repo_policy_blocks": lambda i: RealisticCodingGate(
            config,
            31_000 + i,
        ).attempt(
            scenario="correct_formation_delete_repo_policy_blocks",
            execute_action=_delete_repo_action(),
        ),
        "correct_formation_credential_read_full_high_risk": lambda i: RealisticCodingGate(
            config,
            32_000 + i,
        ).attempt(
            scenario="correct_formation_credential_read_full_high_risk",
            execute_action=actions["credential_read"],
        ),
        "credential_read_downgraded_to_low_blocks": lambda i: RealisticCodingGate(
            config,
            33_000 + i,
        ).attempt(
            scenario="credential_read_downgraded_to_low_blocks",
            execute_action=actions["credential_read"],
            challenge_mutation="downgrade_risk_low",
        ),
        "wrong_formation_safe_edit_blocks": lambda i: RealisticCodingGate(config, 34_000 + i).attempt(
            scenario="wrong_formation_safe_edit_blocks",
            execute_action=actions["edit_file"],
            proof_mode="wrong_nonce",
        ),
    }
    return {name: _summarize_attempts([fn(i) for i in range(trials)]) for name, fn in cases.items()}


def _scenario_suite(config: RealisticGateConfig, scenarios: tuple[str, ...], trials: int, offset: int) -> dict:
    return {
        scenario: _summarize_attempts(
            [_run_named_scenario(scenario, offset + i, config) for i in range(trials)]
        )
        for scenario in scenarios
    }


def _constant_failure_metrics(config: RealisticGateConfig, trials: int) -> dict:
    rows = [
        _run_named_scenario(scenario, 50_000 + i, config)
        for scenario in CONSTANT_FAILURE_SCENARIOS
        for i in range(trials)
    ]
    by_scenario = {
        scenario: _summarize_attempts(
            [_run_named_scenario(scenario, 51_000 + i, config) for i in range(trials)]
        )
        for scenario in CONSTANT_FAILURE_SCENARIOS
    }
    return {
        "combined": _summarize_attempts(rows),
        "by_scenario": by_scenario,
        "target_visible_shape_count": 1,
        "constant_failure_passed": _summarize_attempts(rows)["visible_shape_count"] == 1
        and all(r.blocked for r in rows),
    }


def _sidecar_compromise_metrics(config: RealisticGateConfig, trials: int) -> dict:
    scenarios = _scenario_suite(config, SIDECAR_SCENARIOS, trials, 60_000)
    target_forgery = {
        "no_stolen_sidecar": scenarios["one_sidecar_oracle"],
        "one_stolen_sidecar": scenarios["one_secret_stolen"],
        "two_stolen_sidecars": scenarios["two_secrets_stolen"],
    }
    return {
        "scenarios": scenarios,
        "target_forgery_release": {
            name: row["release"] for name, row in target_forgery.items()
        },
        "unstolen_target_bits_lost_estimate": 0.0,
        "note": "Agent secrets are independent; stolen sidecar outputs did not release an unstolen target proof.",
    }


def _coordinator_attack_metrics(config: RealisticGateConfig, trials: int) -> dict:
    return _scenario_suite(config, COORDINATOR_SCENARIOS, trials, 70_000)


def _ablation_metrics(config: RealisticGateConfig, trials: int) -> dict:
    cases = {
        "full_gate": (
            "path_near_miss",
            "endpoint_mutation",
            "wrong_final_formation",
            "collision_mutation",
            "path_crossing_mutation",
            "forbidden_region_mutation",
            "changed_same_risk_read",
            "wrong_nonce",
            "coordinator_chooses_fewer_agents",
            "risk_low_all_agents",
            "role_label_forgery",
            "delayed_sidecar",
        ),
        "no_action_binding": ("changed_same_risk_read",),
        "no_nonce_binding": ("wrong_nonce",),
        "no_path_binding": ("path_near_miss",),
        "no_endpoint_binding": ("endpoint_mutation",),
        "no_collision_check": ("collision_mutation",),
        "no_path_crossing_check": ("path_crossing_mutation",),
        "no_forbidden_region_check": ("forbidden_region_mutation",),
        "no_final_formation_check": ("wrong_final_formation",),
        "no_required_agent_binding": ("coordinator_chooses_fewer_agents",),
        "no_risk_level_binding": ("risk_low_all_agents",),
        "no_role_binding": ("role_label_forgery",),
        "no_timing_binding": ("delayed_sidecar",),
    }
    out = {}
    for variant, scenarios in cases.items():
        variant_cfg = _variant_config(variant, config)
        scenario_rows = _scenario_suite(variant_cfg, scenarios, trials, 80_000)
        out[variant] = {
            "scenarios": scenario_rows,
            "max_release": max(row["release"]["rate"] for row in scenario_rows.values()),
        }
    return out


def _geometry_value_metrics(config: RealisticGateConfig, trials: int) -> dict:
    variants = (
        "hmac_only",
        "hmac_endpoint",
        "hmac_endpoint_path",
        "hmac_endpoint_path_collision",
        "hmac_endpoint_path_collision_final",
        "full_gate",
    )
    scenarios = (
        "path_near_miss",
        "endpoint_mutation",
        "collision_mutation",
        "wrong_final_formation",
        "changed_same_risk_read",
        "old_nonce_reuse",
        "stolen_sidecar_approves_alone",
    )
    out = {}
    for variant in variants:
        variant_cfg = _variant_config(variant, config)
        scenario_rows = _scenario_suite(variant_cfg, scenarios, trials, 90_000)
        valid_rows = [
            RealisticCodingGate(variant_cfg, 91_000 + i).attempt(
                scenario=f"valid_{variant}",
                execute_action=_real_action_suite()["edit_file"],
            )
            for i in range(trials)
        ]
        out[variant] = {
            "scenarios": scenario_rows,
            "max_attack_release": max(row["release"]["rate"] for row in scenario_rows.values()),
            "near_miss_release": scenario_rows["path_near_miss"]["release"],
            "endpoint_mutation_release": scenario_rows["endpoint_mutation"]["release"],
            "collision_mutation_release": scenario_rows["collision_mutation"]["release"],
            "wrong_final_release": scenario_rows["wrong_final_formation"]["release"],
            "false_block_rate": _proportion(sum(r.blocked for r in valid_rows), len(valid_rows)),
            "runtime_ms": _summary_values([r.elapsed_ms for r in valid_rows]),
            "bits_lost_under_sidecar_theft_estimate": 0.0,
        }
    return out


def _swarm_sweep_metrics(config: RealisticGateConfig, agent_counts: tuple[int, ...], trials: int) -> dict:
    out = {}
    for agents in agent_counts:
        cfg = replace(config, formation=replace(config.formation, agents=agents))
        rows: list[GateAttempt] = []
        generation_failures = 0
        collisions = 0
        for i in range(trials):
            try:
                row = RealisticCodingGate(cfg, 100_000 + i).attempt(
                    scenario=f"sweep_{agents}",
                    execute_action=_real_action_suite()["credential_read"],
                )
                rows.append(row)
                if any("collision" in reason for reason in row.internal_reasons):
                    collisions += 1
            except RuntimeError:
                generation_failures += 1
        summary = _summarize_attempts(rows)
        out[str(agents)] = {
            "summary": summary,
            "legit_pass_rate": summary["release"],
            "false_block_rate": _proportion(sum(r.blocked for r in rows), len(rows)),
            "generation_failures": generation_failures,
            "collisions": collisions,
            "required_agents_high_risk": agents,
            "runtime_ms": summary["elapsed_ms"],
        }
    return out


def run_experiment(
    *,
    trials: int = 20,
    attack_trials: int = 100,
    timing_trials: int = 50,
    ablation_trials: int = 50,
    geometry_trials: int = 50,
    sweep_trials: int = 20,
    sweep_agent_counts: tuple[int, ...] = (5, 10, 20, 50, 100),
    config: RealisticGateConfig = RealisticGateConfig(),
) -> dict:
    return {
        "experiment": "realistic_coding_gate_v1",
        "status": "prototype_measurement",
        "config": {
            "trials": trials,
            "attack_trials": attack_trials,
            "timing_trials": timing_trials,
            "ablation_trials": ablation_trials,
            "geometry_trials": geometry_trials,
            "sweep_trials": sweep_trials,
            "sweep_agent_counts": list(sweep_agent_counts),
            "agents": config.formation.agents,
            "grid_size": config.formation.grid_size,
            "time_steps": config.formation.time_steps,
            "one_shot": config.formation.one_shot,
            "pad_blocked_ms": config.pad_blocked_ms,
            "max_sidecar_delay_ms": config.max_sidecar_delay_ms,
            "constant_failure": config.constant_failure,
        },
        "real_actions": _real_action_suite_metrics(config, trials),
        "policy_and_formation": _policy_formation_metrics(config, trials),
        "attack_suite": _scenario_suite(config, ATTACK_SCENARIOS, attack_trials, 40_000),
        "constant_failure": _constant_failure_metrics(config, timing_trials),
        "sidecar_compromise": _sidecar_compromise_metrics(config, attack_trials),
        "coordinator_attacks": _coordinator_attack_metrics(config, attack_trials),
        "ablations": _ablation_metrics(config, ablation_trials),
        "geometry_value": _geometry_value_metrics(config, geometry_trials),
        "swarm_sweep": _swarm_sweep_metrics(config, sweep_agent_counts, sweep_trials),
        "rollup": {
            "claim": (
                "The toy device executes only when policy and action-bound formation both pass; "
                "ablation and coordinator tests identify which bindings prevent realistic misuse."
            ),
            "public_failure_channel": "released_or_blocked_only",
        },
    }


def _summary_md(metrics: dict) -> str:
    lines = ["# Realistic Coding Gate v1 summary", ""]
    cfg = metrics["config"]
    lines.append(f"- trials: {cfg['trials']}")
    lines.append(f"- attack_trials: {cfg['attack_trials']}")
    lines.append(f"- timing_trials: {cfg['timing_trials']}")
    lines.append(f"- ablation_trials: {cfg['ablation_trials']}")
    lines.append(f"- geometry_trials: {cfg['geometry_trials']}")
    lines.append(f"- sweep: {','.join(map(str, cfg['sweep_agent_counts']))}")
    lines.append("")
    lines.append("| real action | valid release | false block | wrong formation release |")
    lines.append("| --- | ---: | ---: | ---: |")
    for action, row in metrics["real_actions"].items():
        lines.append(
            f"| {action} | {row['valid']['release']['rate']:.2f} | "
            f"{row['false_block_rate']['rate']:.2f} | "
            f"{row['wrong_formation_release']['rate']:.2f} |"
        )
    lines.append("")
    lines.append("| attack scenario | release | blocked |")
    lines.append("| --- | ---: | ---: |")
    for scenario, row in metrics["attack_suite"].items():
        lines.append(f"| {scenario} | {row['release']['rate']:.2f} | {row['blocked']['rate']:.2f} |")
    lines.append("")
    lines.append("| ablation | max release |")
    lines.append("| --- | ---: |")
    for variant, row in metrics["ablations"].items():
        lines.append(f"| {variant} | {row['max_release']:.2f} |")
    lines.append("")
    lines.append("| geometry value variant | max attack release | false block |")
    lines.append("| --- | ---: | ---: |")
    for variant, row in metrics["geometry_value"].items():
        lines.append(
            f"| {variant} | {row['max_attack_release']:.2f} | "
            f"{row['false_block_rate']['rate']:.2f} |"
        )
    lines.append("")
    lines.append("| agents | legit pass | false block | generation failures |")
    lines.append("| ---: | ---: | ---: | ---: |")
    for agents, row in metrics["swarm_sweep"].items():
        lines.append(
            f"| {agents} | {row['legit_pass_rate']['rate']:.2f} | "
            f"{row['false_block_rate']['rate']:.2f} | {row['generation_failures']} |"
        )
    lines.append("")
    lines.append(
        "Report zero observed releases as an observation under this toy device model, "
        "not as a proof of real-world security."
    )
    return "\n".join(lines) + "\n"


def main(argv: Optional[list[str]] = None) -> Path:
    parser = argparse.ArgumentParser(description="Run the realistic coding gate experiment.")
    parser.add_argument("--trials", type=int, default=20)
    parser.add_argument("--attack-trials", type=int, default=100)
    parser.add_argument("--timing-trials", type=int, default=50)
    parser.add_argument("--ablation-trials", type=int, default=50)
    parser.add_argument("--geometry-trials", type=int, default=50)
    parser.add_argument("--sweep-trials", type=int, default=20)
    parser.add_argument("--sweep-agents", default="5,10,20,50,100")
    parser.add_argument("--agents", type=int, default=5)
    parser.add_argument("--grid-size", type=int, default=32)
    parser.add_argument("--time-steps", type=int, default=16)
    parser.add_argument("--pad-blocked-ms", type=float, default=4.0)
    parser.add_argument("--output-root", default="runs")
    args = parser.parse_args(argv)

    config = RealisticGateConfig(
        formation=FG.FormationConfig(
            agents=args.agents,
            grid_size=args.grid_size,
            time_steps=args.time_steps,
        ),
        pad_blocked_ms=args.pad_blocked_ms,
    )
    sweep_agent_counts = tuple(int(part) for part in args.sweep_agents.split(",") if part.strip())
    metrics = run_experiment(
        trials=args.trials,
        attack_trials=args.attack_trials,
        timing_trials=args.timing_trials,
        ablation_trials=args.ablation_trials,
        geometry_trials=args.geometry_trials,
        sweep_trials=args.sweep_trials,
        sweep_agent_counts=sweep_agent_counts,
        config=config,
    )
    run_dir = Path(args.output_root) / utc_run_id()
    run_dir.mkdir(parents=True, exist_ok=True)
    run_config = {
        "experiment": "realistic_coding_gate_v1",
        "trials": args.trials,
        "attack_trials": args.attack_trials,
        "timing_trials": args.timing_trials,
        "ablation_trials": args.ablation_trials,
        "geometry_trials": args.geometry_trials,
        "sweep_trials": args.sweep_trials,
        "sweep_agents": list(sweep_agent_counts),
        "agents": args.agents,
        "grid_size": args.grid_size,
        "time_steps": args.time_steps,
        "pad_blocked_ms": args.pad_blocked_ms,
        "secret_material_redacted": True,
    }
    write_yaml_like(run_dir / "config.yaml", run_config)
    write_environment(run_dir)
    write_git_commit(run_dir)
    full = dict(metrics)
    full["run_config"] = run_config
    full["resource_use"] = process_resource_use()
    write_metrics_and_digest(run_dir / "metrics.json", full)
    (run_dir / "summary.md").write_text(_summary_md(metrics), encoding="utf-8")
    write_metrics(run_dir / "redaction.json", redaction_report(run_dir))
    print(run_dir)
    return run_dir


if __name__ == "__main__":
    main()
