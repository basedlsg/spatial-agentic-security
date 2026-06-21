"""Minimal Core Gate v1.

This experiment compresses Real Sandbox Gate v3 into three named layers:
wrapper, sandbox, and geometry. The goal is not to add coverage. The goal is to
show which pieces have a clear empirical job by removing one piece at a time and
recording the attack class that starts to release.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import platform
import subprocess
import tempfile
import time
from collections import Counter
from dataclasses import asdict, dataclass, replace
from pathlib import Path
from typing import Optional

from spatial_swarm.crypto.hashing import sha256_hex
from spatial_swarm.experiments.metrics import (
    process_resource_use,
    write_metrics,
    write_metrics_and_digest,
)
from spatial_swarm.experiments.redaction import redaction_report
from spatial_swarm.experiments.report import utc_run_id, write_git_commit
from spatial_swarm.spatial_puzzle.experiments import formation_gate as FG
from spatial_swarm.spatial_puzzle.experiments import real_sandbox_gate_v3 as V3
from spatial_swarm.spatial_puzzle.sandbox import ContainerAdapter, EffectRecord, SandboxSpec


VALID_ACTION_TYPES = V3.VALID_ACTION_TYPES

GEOMETRY_AUTH_ATTACKS = (
    "fake_agent",
    "wrong_formation",
    "wrong_nonce",
    "wrong_action",
    "wrong_path",
    "wrong_endpoint",
    "role_swap",
    "stolen_sidecar_approves_alone",
    "two_stolen_sidecars_approve_alone",
    "coordinator_chooses_fewer_agents",
)
EFFECT_MISMATCH_ATTACKS = V3.EFFECT_MISMATCH_ATTACKS
BOUNDARY_ATTACKS = (
    "path_traversal",
    "symlink_escape",
    "absolute_path",
    "encoded_path",
    "shell_command",
    "python_c_danger",
    "environment_injection",
    "working_directory_trick",
    "network_attempt",
    "git_remote_swap",
    "credential_handle_swap",
)
TRANSACTION_SCENARIOS = (
    "valid_read_edit_tests",
    "mid_transaction_swap",
    "reordered_sequence",
    "read_edit_delete",
    "hidden_command_disguised_as_test",
    "credential_inserted_mid_transaction",
    "split_low_risk_exfiltration",
)
ABLATIONS = (
    "full_minimal_core",
    "no_geometry",
    "no_effect_binding",
    "no_transaction_binding",
    "no_container",
    "no_command_allowlist",
    "no_network_isolation",
    "no_path_canonicalization",
    "no_symlink_check",
    "no_env_lock",
    "no_credential_broker",
    "no_git_remote_check",
)
CONSTANT_FAILURE_SCENARIOS = (
    "fake_agent",
    "path_traversal",
    "shell_command",
    "credential_handle_swap",
    "mid_transaction_swap",
)


@dataclass(frozen=True)
class MinimalGuard:
    geometry_enabled: bool = True
    container_enabled: bool = True
    network_isolation: bool = True
    path_canonicalization: bool = True
    symlink_check: bool = True
    env_lock: bool = True
    command_allowlist: bool = True
    effect_binding: bool = True
    credential_broker: bool = True
    git_remote_check: bool = True
    transaction_binding: bool = True
    constant_visible_failure: bool = True
    min_block_ms: float = 4.0
    public_log_bytes: int = V3.PUBLIC_LOG_BYTES
    container_image: str = "slop-code:python3.12"

    def v3(self) -> V3.GuardConfig:
        return V3.GuardConfig(
            container_enabled=self.container_enabled,
            network_isolation=self.network_isolation,
            path_canonicalization=self.path_canonicalization,
            symlink_check=self.symlink_check,
            env_lock=self.env_lock,
            command_allowlist=self.command_allowlist,
            effect_binding=self.effect_binding,
            credential_broker=self.credential_broker,
            git_remote_check=self.git_remote_check,
            transaction_binding=self.transaction_binding,
            constant_visible_failure=self.constant_visible_failure,
            min_block_ms=self.min_block_ms,
            public_log_bytes=self.public_log_bytes,
            container_image=self.container_image,
        )


class MinimalFormationVerifier:
    def __init__(self, trial_index: int) -> None:
        self.trial_index = trial_index
        self.arm = FG.FormationArm("coordinated_formation", FG.FormationConfig(), trial_index)

    def challenge(self, env: V3.ActionEnvelopeV3) -> FG.FormationChallenge:
        for counter in range(128):
            nonce = sha256_hex(
                {
                    "kind": "minimal_core_valid_formation_nonce",
                    "base_nonce": env.nonce,
                    "trial_index": self.trial_index,
                    "counter": counter,
                }
            )[:32]
            challenge = FG.FormationChallenge(
                arm=self.arm.name,
                action_hash=env.action_hash,
                nonce=nonce,
                risk=env.risk_level,
                required_agents=env.required_agents,
            )
            ok, _ = self.arm.formation_valid(challenge)
            if ok:
                return challenge
        raise RuntimeError("failed to generate minimal-core formation challenge")

    def verify(self, env: V3.ActionEnvelopeV3, attack: str = "valid") -> tuple[bool, tuple[str, ...]]:
        challenge = self.challenge(env)
        proofs = list(FG._legit_proofs(self.arm, challenge))
        reasons: list[str] = []

        if attack == "valid":
            pass
        elif attack == "fake_agent":
            proofs[0] = FG.AgentProof(
                "agent_999",
                challenge.action_hash,
                challenge.nonce,
                "fake_path",
                "fake_endpoint",
                "fake_tag",
            )
        elif attack == "wrong_formation":
            p = proofs[0]
            proofs[0] = replace(p, tag=FG._mutate_hex(p.tag))
        elif attack == "wrong_nonce":
            p = proofs[0]
            proofs[0] = replace(p, nonce=FG._mutate_hex(p.nonce))
        elif attack == "wrong_action":
            p = proofs[0]
            proofs[0] = replace(p, action_hash=FG._mutate_hex(p.action_hash))
        elif attack == "wrong_path":
            p = proofs[0]
            proofs[0] = replace(p, path_digest=FG._mutate_hex(p.path_digest))
        elif attack == "wrong_endpoint":
            p = proofs[0]
            proofs[0] = replace(p, endpoint_digest=FG._mutate_hex(p.endpoint_digest))
        elif attack == "role_swap":
            if len(proofs) >= 2:
                p0, p1 = proofs[0], proofs[1]
                proofs[0] = replace(p0, agent_id=p1.agent_id)
                proofs[1] = replace(p1, agent_id=p0.agent_id)
        elif attack == "stolen_sidecar_approves_alone":
            proofs = proofs[:1]
        elif attack == "two_stolen_sidecars_approve_alone":
            proofs = proofs[:2]
        elif attack == "coordinator_chooses_fewer_agents":
            challenge = replace(challenge, risk="low", required_agents=challenge.required_agents[:2])
        else:
            raise ValueError(attack)

        decision = FG.SpatialFormationGate(self.arm).verify(challenge, tuple(proofs))
        reasons.extend(decision.internal_reasons)
        return (not reasons and decision.released), tuple(sorted(set(reasons)))


def _blocked(
    suite: str,
    scenario: str,
    trial_index: int,
    guard: MinimalGuard,
    started: float,
    reasons: list[str],
    *,
    policy_allowed: bool = False,
    formation_released: bool = False,
    contained_started: bool = False,
    effect_violation: bool = False,
    actual_effect: EffectRecord = EffectRecord(),
    allowed_effect: EffectRecord = EffectRecord(),
    raw_credential_leaked: bool = False,
    container_backend: str = "docker",
) -> V3.V3Decision:
    return V3._blocked_decision(
        suite,
        scenario,
        trial_index,
        guard.v3(),
        started,
        reasons,
        policy_allowed=policy_allowed,
        formation_released=formation_released,
        contained_started=contained_started,
        effect_violation=effect_violation,
        actual_effect=actual_effect,
        allowed_effect=allowed_effect,
        raw_credential_leaked=raw_credential_leaked,
        container_backend=container_backend,
    )


def attempt_core_action(
    raw: V3.RawAction,
    *,
    suite: str,
    scenario: str,
    trial_index: int,
    guard: MinimalGuard = MinimalGuard(),
    actual_behavior: str = "declared",
    geometry_attack: str = "valid",
    repo_mutator: Optional[V3.RepoMutator] = None,
) -> V3.V3Decision:
    started = time.perf_counter()
    v3_guard = guard.v3()
    with tempfile.TemporaryDirectory(prefix="spatial-min-core-canon-") as tmp:
        workspace = Path(tmp)
        adapter_for_template = ContainerAdapter(v3_guard.spec_for(raw))
        repo = adapter_for_template.create_repo_template(workspace)
        if repo_mutator is not None:
            repo_mutator(repo, workspace)
        env = V3.ActionCanonicalizerV3(repo, guard=v3_guard, raw=raw).envelope(
            nonce_label=f"{scenario}:{trial_index}"
        )

    policy_allowed, policy_reason = V3.PolicyGateV3(v3_guard).evaluate(env)
    if not policy_allowed:
        return _blocked(
            suite,
            scenario,
            trial_index,
            guard,
            started,
            [f"policy:{policy_reason}"],
            allowed_effect=env.allowed_effects,
        )

    if guard.geometry_enabled:
        formation_released, formation_reasons = MinimalFormationVerifier(trial_index).verify(
            env,
            attack=geometry_attack,
        )
        if not formation_released:
            return _blocked(
                suite,
                scenario,
                trial_index,
                guard,
                started,
                [f"formation:{reason}" for reason in formation_reasons],
                policy_allowed=True,
                allowed_effect=env.allowed_effects,
            )
    else:
        formation_released = True

    network_untraced = actual_behavior == "network_attempt_untraced" and not guard.network_isolation
    adapter_behavior = "declared" if network_untraced else actual_behavior
    result = ContainerAdapter(v3_guard.spec_for(raw)).execute(
        env,
        actual_behavior=adapter_behavior,
        disable_container=not guard.container_enabled,
        repo_mutator=repo_mutator,
    )
    container_backend = "docker" if guard.container_enabled else "host-temp-workspace"
    if result.raw_credential_leaked and guard.credential_broker:
        return _blocked(
            suite,
            scenario,
            trial_index,
            guard,
            started,
            ["credential:raw_value_exposed"],
            policy_allowed=True,
            formation_released=formation_released,
            contained_started=True,
            effect_violation=result.effect_violation,
            actual_effect=result.actual_effects,
            allowed_effect=result.allowed_effects,
            raw_credential_leaked=True,
            container_backend=container_backend,
        )
    if result.effect_violation and guard.effect_binding:
        return _blocked(
            suite,
            scenario,
            trial_index,
            guard,
            started,
            list(result.internal_reasons or ("effect:mismatch",)),
            policy_allowed=True,
            formation_released=formation_released,
            contained_started=True,
            effect_violation=True,
            actual_effect=result.actual_effects,
            allowed_effect=result.allowed_effects,
            raw_credential_leaked=result.raw_credential_leaked,
            container_backend=container_backend,
        )

    elapsed = (time.perf_counter() - started) * 1000
    return V3.V3Decision(
        suite=suite,
        scenario=scenario,
        trial_index=trial_index,
        released=True,
        executed=True,
        blocked=False,
        policy_allowed=True,
        formation_released=formation_released,
        contained_started=True,
        effect_violation=result.effect_violation,
        public_reason="released",
        visible_checks=48,
        public_event_count=3,
        public_log_bytes=128,
        killed_session=False,
        elapsed_ms=elapsed,
        internal_reasons=(),
        actual_effect=result.actual_effects,
        allowed_effect=result.allowed_effects,
        raw_credential_leaked=result.raw_credential_leaked,
        unapproved_network_released=network_untraced,
        unapproved_git_remote_released=(
            raw.action_type == "push"
            and raw.git_remote not in SandboxSpec().allowed_git_remotes
            and not guard.git_remote_check
        ),
        path_escape_released=(
            raw.action_type in {"read_file", "edit_file", "delete_file"}
            and (".." in raw.target or raw.target.startswith("/") or scenario == "symlink_escape")
            and not (guard.path_canonicalization and guard.symlink_check)
        ),
        command_injection_released=raw.action_type in {"run_command", "run_tests"} and not guard.command_allowlist,
        container_backend=container_backend,
    )


def run_valid_action(action_type: str, trial_index: int, guard: MinimalGuard = MinimalGuard()) -> V3.V3Decision:
    return attempt_core_action(
        V3._default_raw(action_type),
        suite="valid_action",
        scenario=action_type,
        trial_index=trial_index,
        guard=guard,
    )


def run_geometry_attack(
    name: str,
    trial_index: int,
    guard: MinimalGuard = MinimalGuard(),
) -> V3.V3Decision:
    return attempt_core_action(
        V3._default_raw("credential_read"),
        suite="geometry_authorization",
        scenario=name,
        trial_index=trial_index,
        guard=guard,
        geometry_attack=name,
    )


def run_effect_attack(
    name: str,
    trial_index: int,
    guard: MinimalGuard = MinimalGuard(),
) -> V3.V3Decision:
    case = V3._case_for_effect(name)
    return attempt_core_action(
        case.raw,
        suite="effect_mismatch",
        scenario=name,
        trial_index=trial_index,
        guard=guard,
        actual_behavior=case.actual_behavior,
    )


def _boundary_case(name: str) -> V3.AttackCase:
    mapping = {
        "path_traversal": "path_traversal_outside",
        "symlink_escape": "symlink_escape",
        "absolute_path": "absolute_path_tmp",
        "encoded_path": "encoded_path_traversal",
        "shell_command": "bash_c",
        "python_c_danger": "python_c_danger",
        "environment_injection": "env_injection",
        "working_directory_trick": "working_directory_trick",
        "network_attempt": "python_socket_attempt",
        "git_remote_swap": "remote_swap",
        "credential_handle_swap": "credential_handle_swap",
    }
    return V3.attack_case(mapping[name])


def run_boundary_attack(
    name: str,
    trial_index: int,
    guard: MinimalGuard = MinimalGuard(),
) -> V3.V3Decision:
    case = _boundary_case(name)
    return attempt_core_action(
        case.raw,
        suite="boundary",
        scenario=name,
        trial_index=trial_index,
        guard=guard,
        actual_behavior=case.actual_behavior,
        repo_mutator=case.repo_mutator,
    )


def run_transaction_scenario(
    name: str,
    trial_index: int,
    guard: MinimalGuard = MinimalGuard(),
) -> V3.V3Decision:
    mapping = {
        "valid_read_edit_tests": "valid_read_edit_tests",
        "mid_transaction_swap": "mid_transaction_swap",
        "reordered_sequence": "reordered_sequence",
        "read_edit_delete": "read_edit_delete",
        "hidden_command_disguised_as_test": "hidden_command_disguised_as_test",
        "credential_inserted_mid_transaction": "credential_read_inserted_mid_transaction",
        "split_low_risk_exfiltration": "split_low_risk_exfiltration",
    }
    row = V3.run_transaction_scenario(mapping[name], trial_index, guard.v3())
    return replace(row, suite="transaction", scenario=name)


def _guard_for_ablation(name: str, base: MinimalGuard) -> MinimalGuard:
    if name == "full_minimal_core":
        return base
    if name == "no_geometry":
        return replace(base, geometry_enabled=False)
    if name == "no_effect_binding":
        return replace(base, effect_binding=False)
    if name == "no_transaction_binding":
        return replace(base, transaction_binding=False)
    if name == "no_container":
        return replace(base, container_enabled=False)
    if name == "no_command_allowlist":
        return replace(base, command_allowlist=False)
    if name == "no_network_isolation":
        return replace(base, network_isolation=False)
    if name == "no_path_canonicalization":
        return replace(base, path_canonicalization=False)
    if name == "no_symlink_check":
        return replace(base, symlink_check=False)
    if name == "no_env_lock":
        return replace(base, env_lock=False)
    if name == "no_credential_broker":
        return replace(base, credential_broker=False)
    if name == "no_git_remote_check":
        return replace(base, git_remote_check=False)
    raise ValueError(name)


def run_ablation_case(name: str, trial_index: int, base: MinimalGuard = MinimalGuard()) -> V3.V3Decision:
    guard = _guard_for_ablation(name, base)
    if name == "full_minimal_core":
        row = run_effect_attack("read_file_writes_file", trial_index, guard)
    elif name == "no_geometry":
        row = run_geometry_attack(GEOMETRY_AUTH_ATTACKS[trial_index % len(GEOMETRY_AUTH_ATTACKS)], trial_index, guard)
    elif name == "no_effect_binding":
        row = run_effect_attack("read_file_writes_file", trial_index, guard)
    elif name == "no_transaction_binding":
        row = run_transaction_scenario("mid_transaction_swap", trial_index, guard)
    elif name == "no_container":
        row = attempt_core_action(
            V3._default_raw("run_tests"),
            suite="ablation",
            scenario=name,
            trial_index=trial_index,
            guard=guard,
        )
    elif name == "no_command_allowlist":
        row = attempt_core_action(
            V3.RawAction("run_command", args=("sh", "-c", "echo command escape")),
            suite="ablation",
            scenario=name,
            trial_index=trial_index,
            guard=guard,
        )
    elif name == "no_network_isolation":
        row = attempt_core_action(
            V3._default_raw("run_tests"),
            suite="ablation",
            scenario=name,
            trial_index=trial_index,
            guard=guard,
            actual_behavior="network_attempt_untraced",
        )
    elif name == "no_path_canonicalization":
        case = V3._case_for_filesystem("path_traversal_outside")
        row = attempt_core_action(
            case.raw,
            suite="ablation",
            scenario=name,
            trial_index=trial_index,
            guard=guard,
            repo_mutator=case.repo_mutator,
        )
    elif name == "no_symlink_check":
        case = V3._case_for_filesystem("symlink_escape")
        row = attempt_core_action(
            case.raw,
            suite="ablation",
            scenario=name,
            trial_index=trial_index,
            guard=guard,
            repo_mutator=case.repo_mutator,
        )
        row = replace(row, path_escape_released=row.released)
    elif name == "no_env_lock":
        row = attempt_core_action(
            V3.RawAction("run_tests", args=V3._default_raw("run_tests").args, env={"TOKEN": "not-a-real-token"}),
            suite="ablation",
            scenario=name,
            trial_index=trial_index,
            guard=guard,
        )
    elif name == "no_credential_broker":
        case = V3._case_for_credential("credential_print_attempt")
        row = attempt_core_action(
            case.raw,
            suite="ablation",
            scenario=name,
            trial_index=trial_index,
            guard=guard,
            actual_behavior=case.actual_behavior,
        )
    elif name == "no_git_remote_check":
        row = attempt_core_action(
            V3.RawAction("push", git_remote="evil-remote"),
            suite="ablation",
            scenario=name,
            trial_index=trial_index,
            guard=guard,
        )
    else:
        raise ValueError(name)
    return replace(row, suite="ablation", scenario=name)


def run_constant_failure_case(
    name: str,
    trial_index: int,
    guard: MinimalGuard = MinimalGuard(),
) -> V3.V3Decision:
    if name in GEOMETRY_AUTH_ATTACKS:
        return run_geometry_attack(name, trial_index, guard)
    if name in BOUNDARY_ATTACKS:
        return run_boundary_attack(name, trial_index, guard)
    if name in TRANSACTION_SCENARIOS:
        return run_transaction_scenario(name, trial_index, guard)
    raise ValueError(name)


def _counts(mode: str) -> dict[str, int]:
    if mode == "smoke":
        return {
            "valid_trials": 20,
            "attack_trials": 50,
            "ablation_trials": 20,
            "transaction_trials": 20,
            "constant_failure_trials": 20,
        }
    if mode == "core":
        return {
            "valid_trials": 100,
            "attack_trials": 200,
            "ablation_trials": 100,
            "transaction_trials": 100,
            "constant_failure_trials": 100,
        }
    if mode == "full":
        return {
            "valid_trials": 200,
            "attack_trials": 500,
            "ablation_trials": 200,
            "transaction_trials": 300,
            "constant_failure_trials": 500,
        }
    raise ValueError(mode)


def summarize(rows: list[V3.V3Decision]) -> dict:
    out = V3.summarize(rows)
    out["geometry_auth_release"] = out["release"]
    return out


def _by_name(rows: list[V3.V3Decision], names: tuple[str, ...]) -> dict[str, dict]:
    return {name: summarize([row for row in rows if row.scenario == name]) for name in names}


def _release_rate(rows: list[V3.V3Decision], *, exclude: set[str] = frozenset()) -> float:
    selected = [row for row in rows if row.scenario not in exclude]
    return sum(row.released for row in selected) / len(selected) if selected else 0.0


def run_experiment(
    *,
    mode: str = "smoke",
    valid_trials: Optional[int] = None,
    attack_trials: Optional[int] = None,
    ablation_trials: Optional[int] = None,
    transaction_trials: Optional[int] = None,
    constant_failure_trials: Optional[int] = None,
    guard: MinimalGuard = MinimalGuard(),
) -> tuple[dict, dict[str, list[V3.V3Decision]]]:
    counts = _counts(mode)
    if valid_trials is not None:
        counts["valid_trials"] = valid_trials
    if attack_trials is not None:
        counts["attack_trials"] = attack_trials
    if ablation_trials is not None:
        counts["ablation_trials"] = ablation_trials
    if transaction_trials is not None:
        counts["transaction_trials"] = transaction_trials
    if constant_failure_trials is not None:
        counts["constant_failure_trials"] = constant_failure_trials

    valid_rows = [
        run_valid_action(action, trial, guard)
        for action in VALID_ACTION_TYPES
        for trial in range(counts["valid_trials"])
    ]
    geometry_rows = [
        run_geometry_attack(name, trial, guard)
        for name in GEOMETRY_AUTH_ATTACKS
        for trial in range(counts["attack_trials"])
    ]
    effect_rows = [
        run_effect_attack(name, trial, guard)
        for name in EFFECT_MISMATCH_ATTACKS
        for trial in range(counts["attack_trials"])
    ]
    boundary_rows = [
        run_boundary_attack(name, trial, guard)
        for name in BOUNDARY_ATTACKS
        for trial in range(counts["attack_trials"])
    ]
    transaction_rows = [
        run_transaction_scenario(name, trial, guard)
        for name in TRANSACTION_SCENARIOS
        for trial in range(counts["transaction_trials"])
    ]
    ablation_rows = [
        run_ablation_case(name, trial, guard)
        for name in ABLATIONS
        for trial in range(counts["ablation_trials"])
    ]
    constant_rows = [
        run_constant_failure_case(name, trial, guard)
        for name in CONSTANT_FAILURE_SCENARIOS
        for trial in range(counts["constant_failure_trials"])
    ]

    valid_false_blocks = sum(row.blocked for row in valid_rows)
    geometry_attack_releases = sum(row.released for row in geometry_rows)
    effect_attack_releases = sum(row.released for row in effect_rows)
    boundary_attack_releases = sum(row.released for row in boundary_rows)
    transaction_attack_releases = sum(
        row.released for row in transaction_rows if row.scenario != "valid_read_edit_tests"
    )
    constant_summary = summarize(constant_rows)
    ablation_summaries = _by_name(ablation_rows, ABLATIONS)
    no_geometry_rows = [
        run_geometry_attack(name, trial, replace(guard, geometry_enabled=False))
        for name in GEOMETRY_AUTH_ATTACKS
        for trial in range(min(counts["ablation_trials"], counts["attack_trials"]))
    ]
    geometry_delta = {
        "with_geometry_release_rate": _release_rate(geometry_rows),
        "without_geometry_release_rate": _release_rate(no_geometry_rows),
        "difference": _release_rate(no_geometry_rows) - _release_rate(geometry_rows),
    }

    variant_table = {
        "full_minimal_core": {
            "valid_actions": valid_false_blocks == 0,
            "geometry_attacks_blocked": geometry_attack_releases == 0,
            "effect_attacks_blocked": effect_attack_releases == 0,
            "boundary_attacks_blocked": boundary_attack_releases == 0,
            "transaction_attacks_blocked": transaction_attack_releases == 0,
        },
        "no_geometry": {
            "geometry_attack_release_rate": ablation_summaries["no_geometry"]["release"]["rate"],
        },
        "no_effect_binding": {
            "effect_attack_release_rate": ablation_summaries["no_effect_binding"]["release"]["rate"],
        },
        "no_transaction_binding": {
            "transaction_swap_release_rate": ablation_summaries["no_transaction_binding"]["transaction_swap_released"]["rate"],
        },
        "no_command_allowlist": {
            "command_attack_release_rate": ablation_summaries["no_command_allowlist"]["release"]["rate"],
        },
        "no_container": {
            "container_backends": ablation_summaries["no_container"]["container_backends"],
            "release_rate": ablation_summaries["no_container"]["release"]["rate"],
        },
    }
    success = {
        "valid_false_blocks": valid_false_blocks,
        "geometry_attack_releases": geometry_attack_releases,
        "effect_attack_releases": effect_attack_releases,
        "boundary_attack_releases": boundary_attack_releases,
        "transaction_attack_releases": transaction_attack_releases,
        "host_effects_detected": sum(row.host_effects_detected for row in valid_rows + boundary_rows),
        "raw_credential_leaks_released": sum(
            row.raw_credential_leaked and row.released for row in boundary_rows + effect_rows
        ),
        "constant_visible_failure_passed": constant_summary["visible_shape_count"] == 1
        and constant_summary["blocked"]["rate"] == 1.0,
        "full_minimal_core_passed": valid_false_blocks == 0
        and geometry_attack_releases == 0
        and effect_attack_releases == 0
        and boundary_attack_releases == 0
        and transaction_attack_releases == 0,
        "geometry_delta": geometry_delta,
        "variant_table": variant_table,
        "ablation_exposures": {
            name: {
                "release_rate": ablation_summaries[name]["release"]["rate"],
                "raw_credential_leak_rate": ablation_summaries[name]["raw_credential_leaked"]["rate"],
                "network_release_rate": ablation_summaries[name]["unapproved_network_released"]["rate"],
                "git_release_rate": ablation_summaries[name]["unapproved_git_remote_released"]["rate"],
                "transaction_swap_release_rate": ablation_summaries[name]["transaction_swap_released"]["rate"],
                "path_escape_release_rate": ablation_summaries[name]["path_escape_released"]["rate"],
                "command_injection_release_rate": ablation_summaries[name]["command_injection_released"]["rate"],
                "container_backends": ablation_summaries[name]["container_backends"],
            }
            for name in ABLATIONS
        },
    }

    metrics = {
        "experiment": "minimal_core_gate_v1",
        "status": "minimal_core_layer_ablation",
        "question": "Which wrapper, sandbox, and geometry pieces are experimentally necessary?",
        "mode": mode,
        "counts": counts,
        "layers": {
            "wrapper": [
                "canonical_action",
                "policy_check",
                "effect_binding",
                "transaction_binding",
                "constant_visible_failure_shape",
            ],
            "sandbox": [
                "container_sandbox",
                "command_allowlist",
                "fixed_environment",
                "fixed_working_directory",
                "network_off",
                "credential_broker",
                "git_remote_guard",
            ],
            "geometry": ["braid_formation_check"],
        },
        "guard": asdict(guard),
        "valid_actions": _by_name(valid_rows, VALID_ACTION_TYPES),
        "geometry_authorization": _by_name(geometry_rows, GEOMETRY_AUTH_ATTACKS),
        "effect_mismatch": _by_name(effect_rows, EFFECT_MISMATCH_ATTACKS),
        "boundary": _by_name(boundary_rows, BOUNDARY_ATTACKS),
        "transactions": _by_name(transaction_rows, TRANSACTION_SCENARIOS),
        "ablations": ablation_summaries,
        "constant_visible_failure": {
            "by_scenario": _by_name(constant_rows, CONSTANT_FAILURE_SCENARIOS),
            "combined": constant_summary,
        },
        "success_criteria": success,
    }
    rows = {
        "valid": valid_rows,
        "geometry": geometry_rows,
        "effect": effect_rows,
        "boundary": boundary_rows,
        "transaction": transaction_rows,
        "ablation": ablation_rows,
        "constant": constant_rows,
        "no_geometry_probe": no_geometry_rows,
    }
    return metrics, rows


def _decision_row(row: V3.V3Decision) -> dict[str, object]:
    return V3._decision_row(row)


def _write_csv(path: Path, rows: list[V3.V3Decision]) -> None:
    fields = list(_decision_row(rows[0]).keys()) if rows else list(_decision_row(V3._empty_decision()).keys())
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in rows:
            writer.writerow(_decision_row(row))


def _effect_record_json(row: V3.V3Decision) -> dict:
    return V3._effect_record_json(row)


def _docker_info(container_image: str) -> dict:
    try:
        version = subprocess.check_output(["docker", "version", "--format", "{{json .}}"], text=True)
        image = subprocess.check_output(
            ["docker", "image", "inspect", container_image, "--format", "{{json .Id}}"],
            text=True,
        ).strip()
        return {"available": True, "version": json.loads(version), "image_id": json.loads(image)}
    except Exception as exc:
        return {"available": False, "error": str(exc), "image": container_image}


def _run_environment(container_image: str) -> dict:
    try:
        top = subprocess.check_output(["git", "rev-parse", "--show-toplevel"], text=True).strip()
        commit = subprocess.check_output(["git", "-C", top, "rev-parse", "HEAD"], text=True).strip()
        rel_cwd = os.path.relpath(os.getcwd(), top)
        status = subprocess.check_output(["git", "-C", top, "status", "--short", "--", rel_cwd], text=True).strip()
    except Exception:
        commit = "unknown"
        status = ""
    return {
        "timestamp_utc": utc_run_id(),
        "python": platform.python_version(),
        "platform": platform.platform(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "cwd": os.getcwd(),
        "git_commit": commit,
        "worktree_dirty_scoped_to_project": bool(status),
        "docker": _docker_info(container_image),
    }


def write_run_artifacts(run_dir: Path, metrics: dict, rows: dict[str, list[V3.V3Decision]]) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    write_metrics(run_dir / "minimal_core_config.json", {
        "layers": metrics["layers"],
        "guard": metrics["guard"],
        "mode": metrics["mode"],
        "counts": metrics["counts"],
    })
    _write_csv(run_dir / "valid_action_results.csv", rows["valid"])
    _write_csv(run_dir / "geometry_authorization_results.csv", rows["geometry"])
    _write_csv(run_dir / "effect_mismatch_results.csv", rows["effect"])
    _write_csv(run_dir / "boundary_results.csv", rows["boundary"])
    _write_csv(run_dir / "transaction_results.csv", rows["transaction"])
    _write_csv(run_dir / "ablation_results.csv", rows["ablation"])
    _write_csv(run_dir / "constant_failure_results.csv", rows["constant"])
    with (run_dir / "effect_records.jsonl").open("w", encoding="utf-8") as handle:
        for group in ("valid", "geometry", "effect", "boundary", "transaction", "ablation", "constant", "no_geometry_probe"):
            for row in rows[group]:
                handle.write(json.dumps(_effect_record_json(row), sort_keys=True) + "\n")
    (run_dir / "run_environment.json").write_text(
        json.dumps(_run_environment(metrics["guard"]["container_image"]), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    write_git_commit(run_dir)
    full = dict(metrics)
    full["resource_use"] = process_resource_use()
    write_metrics_and_digest(run_dir / "metrics.json", full)
    write_metrics(run_dir / "redaction.json", redaction_report(run_dir))


def main(argv: Optional[list[str]] = None) -> Path:
    parser = argparse.ArgumentParser(description="Run Minimal Core Gate v1.")
    parser.add_argument("--mode", choices=("smoke", "core", "full"), default="smoke")
    parser.add_argument("--valid-trials", type=int)
    parser.add_argument("--attack-trials", type=int)
    parser.add_argument("--ablation-trials", type=int)
    parser.add_argument("--transaction-trials", type=int)
    parser.add_argument("--constant-failure-trials", type=int)
    parser.add_argument("--output-root", default="runs")
    parser.add_argument("--container-image", default=SandboxSpec().container_image)
    parser.add_argument("--min-block-ms", type=float, default=4.0)
    args = parser.parse_args(argv)
    docker = _docker_info(args.container_image)
    if not docker["available"]:
        raise RuntimeError(f"Docker backend is unavailable: {docker.get('error')}")
    guard = MinimalGuard(container_image=args.container_image, min_block_ms=args.min_block_ms)
    metrics, rows = run_experiment(
        mode=args.mode,
        valid_trials=args.valid_trials,
        attack_trials=args.attack_trials,
        ablation_trials=args.ablation_trials,
        transaction_trials=args.transaction_trials,
        constant_failure_trials=args.constant_failure_trials,
        guard=guard,
    )
    run_dir = Path(args.output_root) / utc_run_id()
    write_run_artifacts(run_dir, metrics, rows)
    print(run_dir)
    return run_dir


if __name__ == "__main__":
    main()
