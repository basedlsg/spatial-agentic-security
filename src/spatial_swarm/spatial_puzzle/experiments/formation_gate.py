"""Spatial Formation Gate stress test.

This experiment is the follow-on to the partial-compromise result. It stops treating
3D as one static shared object and tests a local action gate instead:

* every action gets a fresh challenge,
* each agent proves a private action-bound factor,
* trajectory arms bind the proof to a time-indexed 3D route,
* the coordinated arm also checks final formation and collision rules,
* one wrong formation kills the session.

The first version deliberately keeps the proof simple: HMAC tags over hidden digests.
The point is to measure the security shape of the design, not to claim zero-knowledge
or hardware isolation.
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import math
import random
import statistics
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from spatial_swarm.crypto.hashing import canonical_json, sha256_hex
from spatial_swarm.experiments.metrics import (
    process_resource_use,
    write_metrics,
    write_metrics_and_digest,
)
from spatial_swarm.experiments.redaction import redaction_report
from spatial_swarm.experiments.report import utc_run_id, write_environment, write_git_commit, write_yaml_like
from spatial_swarm.spatial_lab.solvers.base import Budget
from spatial_swarm.spatial_puzzle.generators.build import build_hidden_solution, derive_public_view
from spatial_swarm.spatial_puzzle.generators.visibility import clue_predicate_for, region_for
from spatial_swarm.spatial_puzzle.solvers import pure_enum

ARM_NAMES = (
    "random_baseline",
    "old_shared_object",
    "independent_static_geometry",
    "independent_trajectory",
    "coordinated_formation",
)

ROLES = ("planner", "coder", "tester", "security", "repo_guardian")

ACCESS_LEVELS = {
    "A0_public_only": 0,
    "A2_one_stolen_sidecar": 1,
    "A3_two_stolen_sidecars": 2,
}

ATTACK_SCENARIOS = (
    "replay_old_formation",
    "changed_action_reuse",
    "same_nonce_reuse",
    "one_stolen_sidecar",
    "two_stolen_sidecars",
    "fake_agent",
    "solver_near_miss",
    "model_generated_guess",
    "collision_or_endpoint_mutation",
    "poisoned_tool_metadata_reuse",
    "wrong_timing_nonce",
)


@dataclass(frozen=True)
class FormationConfig:
    agents: int = 5
    grid_size: int = 32
    time_steps: int = 16
    static_k: int = 4
    tag_bits_reported: int = 128
    one_shot: bool = True


@dataclass(frozen=True)
class ActionRequest:
    kind: str
    target: str
    payload: dict

    def canonical(self) -> dict:
        return {"kind": self.kind, "target": self.target, "payload": self.payload}

    def action_hash(self) -> str:
        return sha256_hex({"kind": "formation_gate_action", "action": self.canonical()})


@dataclass(frozen=True)
class FormationChallenge:
    arm: str
    action_hash: str
    nonce: str
    risk: str
    required_agents: tuple[str, ...]

    @property
    def challenge_id(self) -> str:
        return sha256_hex(
            {
                "kind": "formation_gate_challenge",
                "arm": self.arm,
                "action_hash": self.action_hash,
                "nonce": self.nonce,
                "required": self.required_agents,
            }
        )


@dataclass(frozen=True)
class ExpectedTrace:
    path_digest: str
    endpoint_digest: str
    path: tuple[tuple[int, int, int], ...]


@dataclass(frozen=True)
class AgentProof:
    agent_id: str
    action_hash: str
    nonce: str
    path_digest: str
    endpoint_digest: str
    tag: str


@dataclass(frozen=True)
class GateDecision:
    released: bool
    blocked: bool
    state: str
    public_reason: str
    internal_reasons: tuple[str, ...]
    checks_performed: int
    public_reason_bits: float = 0.0


def _agent_ids(n: int) -> tuple[str, ...]:
    return tuple(f"agent_{i + 1:03d}" for i in range(n))


def _role_for_index(i: int) -> str:
    return ROLES[i % len(ROLES)]


def _secret(label: str, *parts) -> bytes:
    return hashlib.sha256(canonical_json({"label": label, "parts": parts}).encode("utf-8")).digest()


def _hmac_hex(secret: bytes, payload: dict) -> str:
    return hmac.new(secret, canonical_json(payload).encode("utf-8"), hashlib.sha256).hexdigest()


def _coord_from_digest(digest: bytes, grid_size: int) -> tuple[int, int, int]:
    return (digest[0] % grid_size, digest[1] % grid_size, digest[2] % grid_size)


def _risk_for_action(action: ActionRequest) -> str:
    text = canonical_json(action.canonical()).lower()
    if action.kind in {"push", "install_package", "credential_read", "dangerous_shell"}:
        return "high"
    if any(token in text for token in ("rm -rf", "api_key", "token", "secret", "curl ", "ssh ")):
        return "high"
    if action.kind in {"edit_file", "run_command", "dependency_change"}:
        return "medium"
    return "low"


def _required_agents(agent_ids: tuple[str, ...], risk: str) -> tuple[str, ...]:
    if risk == "low":
        return (agent_ids[0], agent_ids[-1])
    if risk == "medium":
        return tuple(agent_ids[i] for i in (0, 1, 2, len(agent_ids) - 1))
    return agent_ids


def _digest_path(path: tuple[tuple[int, int, int], ...]) -> str:
    return sha256_hex({"kind": "formation_path", "points": [list(p) for p in path]})


def _digest_endpoint(point: tuple[int, int, int]) -> str:
    return sha256_hex({"kind": "formation_endpoint", "point": list(point)})


def _formation_offsets(agent_count: int, template: int) -> tuple[tuple[int, int, int], ...]:
    base = {
        0: ((0, 0, 0), (6, 0, 0), (0, 6, 0), (0, 0, 6), (6, 6, 6)),
        1: ((0, 0, 0), (4, 0, 4), (8, 0, 0), (4, 6, 4), (4, 3, 9)),
        2: ((0, 0, 0), (2, 3, 1), (4, 6, 2), (6, 9, 3), (8, 12, 4)),
    }[template % 3]
    if agent_count <= len(base):
        return base[:agent_count]
    extra = tuple((i * 2, i * 3, i) for i in range(len(base), agent_count))
    return base + extra


def _linear_path(
    start: tuple[int, int, int],
    end: tuple[int, int, int],
    steps: int,
) -> tuple[tuple[int, int, int], ...]:
    if steps <= 1:
        return (end,)
    out = []
    for t in range(steps):
        frac = t / (steps - 1)
        out.append(
            (
                round(start[0] + (end[0] - start[0]) * frac),
                round(start[1] + (end[1] - start[1]) * frac),
                round(start[2] + (end[2] - start[2]) * frac),
            )
        )
    return tuple(out)


class FormationArm:
    def __init__(self, name: str, config: FormationConfig, trial_index: int) -> None:
        if name not in ARM_NAMES:
            raise ValueError(f"unknown arm: {name}")
        self.name = name
        self.config = config
        self.trial_index = trial_index
        self.agent_ids = _agent_ids(config.agents)
        self.roles = {agent: _role_for_index(i) for i, agent in enumerate(self.agent_ids)}
        self._agent_secrets = {
            agent: _secret("formation_agent", name, trial_index, agent) for agent in self.agent_ids
        }
        self._old_solution = None
        self._old_pieces = {}
        if name == "old_shared_object":
            self._old_solution = build_hidden_solution(
                random.Random(710_000 + trial_index),
                n=config.agents,
                k=config.static_k,
                swarm_id=f"formation-old-{trial_index}",
            )
            self._old_pieces = dict(self._old_solution.pieces)
        self._static_pieces = {
            agent: self._private_static_piece(agent) for agent in self.agent_ids
        }

    def sidecar(self, agent_id: str) -> "AgentSidecar":
        return AgentSidecar(self, agent_id)

    def expected_trace(self, agent_id: str, challenge: FormationChallenge) -> ExpectedTrace:
        if agent_id not in self.agent_ids:
            return ExpectedTrace("missing", "missing", ())
        if self.name == "random_baseline":
            digest = sha256_hex(
                {
                    "kind": "random_baseline_factor",
                    "agent": agent_id,
                    "action_hash": challenge.action_hash,
                    "nonce": challenge.nonce,
                }
            )
            return ExpectedTrace(digest, "none", ())
        if self.name == "old_shared_object":
            piece = self._old_pieces[agent_id]
            piece_digest = sha256_hex({"kind": "old_shared_piece", "cells": sorted(map(list, piece))})
            digest = sha256_hex(
                {
                    "kind": "old_shared_static_factor",
                    "agent": agent_id,
                    "piece_digest": piece_digest,
                    "action_hash": challenge.action_hash,
                    "nonce": challenge.nonce,
                }
            )
            return ExpectedTrace(digest, "none", ())
        if self.name == "independent_static_geometry":
            piece = self._static_pieces[agent_id]
            piece_digest = sha256_hex(
                {"kind": "independent_static_piece", "points": sorted(map(list, piece))}
            )
            digest = sha256_hex(
                {
                    "kind": "independent_static_factor",
                    "agent": agent_id,
                    "piece_digest": piece_digest,
                    "action_hash": challenge.action_hash,
                    "nonce": challenge.nonce,
                }
            )
            return ExpectedTrace(digest, "none", ())
        path = self._private_path(agent_id, challenge)
        return ExpectedTrace(_digest_path(path), _digest_endpoint(path[-1]), path)

    def expected_tag(self, agent_id: str, challenge: FormationChallenge, trace: ExpectedTrace) -> str:
        return _hmac_hex(
            self._agent_secrets[agent_id],
            {
                "kind": "formation_gate_proof",
                "arm": self.name,
                "agent": agent_id,
                "action_hash": challenge.action_hash,
                "nonce": challenge.nonce,
                "path_digest": trace.path_digest,
                "endpoint_digest": trace.endpoint_digest,
            },
        )

    def formation_valid(self, challenge: FormationChallenge) -> tuple[bool, tuple[str, ...]]:
        if self.name != "coordinated_formation":
            return True, ()
        traces = {agent: self.expected_trace(agent, challenge) for agent in challenge.required_agents}
        reasons: list[str] = []
        paths = [trace.path for trace in traces.values()]
        if any(len(path) != self.config.time_steps for path in paths):
            reasons.append("wrong_path_length")
        for t in range(self.config.time_steps):
            occupied = [path[t] for path in paths if len(path) > t]
            if len(occupied) != len(set(occupied)):
                reasons.append("collision")
                break
        for t in range(self.config.time_steps - 1):
            edges = [((path[t], path[t + 1])) for path in paths]
            edge_set = set(edges)
            swapped = any((b, a) in edge_set for a, b in edge_set if a != b)
            if swapped:
                reasons.append("path_crossing")
                break
        forbidden = self._forbidden_points(challenge)
        if any(point in forbidden for path in paths for point in path):
            reasons.append("forbidden_region")
        endpoints = tuple(path[-1] for path in paths)
        if len(endpoints) != len(set(endpoints)):
            reasons.append("endpoint_collision")
        if not self._endpoints_match_template(challenge, endpoints):
            reasons.append("wrong_final_formation")
        return not reasons, tuple(sorted(set(reasons)))

    def _private_static_piece(self, agent_id: str) -> frozenset[tuple[int, int, int]]:
        points: set[tuple[int, int, int]] = set()
        counter = 0
        while len(points) < self.config.static_k:
            points.add(
                _coord_from_digest(
                    _secret("independent_static_point", self.name, self.trial_index, agent_id, counter),
                    self.config.grid_size,
                )
            )
            counter += 1
        return frozenset(points)

    def _private_path(self, agent_id: str, challenge: FormationChallenge) -> tuple[tuple[int, int, int], ...]:
        if self.name == "coordinated_formation":
            return self._coordinated_path(agent_id, challenge)
        points = []
        for t in range(self.config.time_steps):
            points.append(
                _coord_from_digest(
                    _secret(
                        "independent_trajectory_point",
                        self.name,
                        self.trial_index,
                        agent_id,
                        challenge.action_hash,
                        challenge.nonce,
                        t,
                    ),
                    self.config.grid_size,
                )
            )
        return tuple(points)

    def _coordinated_path(self, agent_id: str, challenge: FormationChallenge) -> tuple[tuple[int, int, int], ...]:
        idx = self.agent_ids.index(agent_id)
        endpoint = self._formation_endpoint(agent_id, challenge)
        start_digest = _secret(
            "formation_start",
            self.name,
            self.trial_index,
            agent_id,
            challenge.action_hash,
            challenge.nonce,
        )
        lane = max(1, self.config.grid_size // max(1, self.config.agents))
        start = (
            start_digest[0] % self.config.grid_size,
            min(self.config.grid_size - 1, idx * lane + (start_digest[1] % lane)),
            start_digest[2] % self.config.grid_size,
        )
        return _linear_path(start, endpoint, self.config.time_steps)

    def _formation_endpoint(self, agent_id: str, challenge: FormationChallenge) -> tuple[int, int, int]:
        idx = self.agent_ids.index(agent_id)
        digest = _secret("formation_template", self.trial_index, challenge.action_hash, challenge.nonce)
        template = digest[0] % 3
        margin = 10
        max_anchor = max(1, self.config.grid_size - margin)
        anchor = (
            2 + digest[1] % max_anchor,
            2 + digest[2] % max_anchor,
            2 + digest[3] % max_anchor,
        )
        off = _formation_offsets(self.config.agents, template)[idx]
        return (
            min(self.config.grid_size - 1, anchor[0] + off[0]),
            min(self.config.grid_size - 1, anchor[1] + off[1]),
            min(self.config.grid_size - 1, anchor[2] + off[2]),
        )

    def _endpoints_match_template(
        self, challenge: FormationChallenge, endpoints: tuple[tuple[int, int, int], ...]
    ) -> bool:
        expected = tuple(self._formation_endpoint(agent, challenge) for agent in challenge.required_agents)
        return endpoints == expected

    def _forbidden_points(self, challenge: FormationChallenge) -> frozenset[tuple[int, int, int]]:
        points = set()
        for i in range(6):
            points.add(
                _coord_from_digest(
                    _secret("formation_forbidden", self.trial_index, challenge.action_hash, challenge.nonce, i),
                    self.config.grid_size,
                )
            )
        return frozenset(points)


class AgentSidecar:
    def __init__(self, arm: FormationArm, agent_id: str) -> None:
        if agent_id not in arm.agent_ids:
            raise ValueError(f"unknown agent: {agent_id}")
        self._arm = arm
        self.agent_id = agent_id

    def prove(self, challenge: FormationChallenge) -> AgentProof:
        trace = self._arm.expected_trace(self.agent_id, challenge)
        tag = self._arm.expected_tag(self.agent_id, challenge, trace)
        return AgentProof(
            agent_id=self.agent_id,
            action_hash=challenge.action_hash,
            nonce=challenge.nonce,
            path_digest=trace.path_digest,
            endpoint_digest=trace.endpoint_digest,
            tag=tag,
        )


class SpatialFormationGate:
    def __init__(self, arm: FormationArm) -> None:
        self.arm = arm
        self.state = "alive"
        self._round = 0
        self._used_nonces: set[str] = set()

    def challenge(self, action: ActionRequest) -> FormationChallenge:
        risk = _risk_for_action(action)
        required = _required_agents(self.arm.agent_ids, risk)
        for _ in range(128):
            nonce = sha256_hex(
                {
                    "kind": "formation_gate_nonce",
                    "arm": self.arm.name,
                    "trial_index": self.arm.trial_index,
                    "round": self._round,
                    "action_hash": action.action_hash(),
                }
            )[:32]
            self._round += 1
            challenge = FormationChallenge(
                arm=self.arm.name,
                action_hash=action.action_hash(),
                nonce=nonce,
                risk=risk,
                required_agents=required,
            )
            ok, _ = self.arm.formation_valid(challenge)
            if ok:
                return challenge
        raise RuntimeError("failed to generate a valid formation challenge")

    def verify(self, challenge: FormationChallenge, proofs: tuple[AgentProof, ...]) -> GateDecision:
        reasons: list[str] = []
        checks = 0
        if self.state != "alive":
            reasons.append("session_dead")
        if challenge.arm != self.arm.name:
            reasons.append("wrong_arm")
        if challenge.nonce in self._used_nonces:
            reasons.append("replay_nonce")
        required = set(challenge.required_agents)
        proof_ids = [p.agent_id for p in proofs]
        proof_map = {p.agent_id: p for p in proofs}
        checks += 4
        if len(proofs) != len(proof_map):
            reasons.append("duplicate_agent")
        if set(proof_ids) != required:
            reasons.append("wrong_agent_set")

        for agent in challenge.required_agents:
            proof = proof_map.get(agent)
            trace = self.arm.expected_trace(agent, challenge)
            expected_tag = self.arm.expected_tag(agent, challenge, trace)
            checks += 5
            if proof is None:
                reasons.append("missing_agent")
                continue
            if proof.action_hash != challenge.action_hash:
                reasons.append("wrong_action")
            if proof.nonce != challenge.nonce:
                reasons.append("wrong_nonce")
            if proof.path_digest != trace.path_digest:
                reasons.append("wrong_path_digest")
            if proof.endpoint_digest != trace.endpoint_digest:
                reasons.append("wrong_endpoint_digest")
            if not hmac.compare_digest(proof.tag, expected_tag):
                reasons.append("wrong_tag")

        formation_ok, formation_reasons = self.arm.formation_valid(challenge)
        checks += 6
        if not formation_ok:
            reasons.extend(formation_reasons)

        released = not reasons
        self._used_nonces.add(challenge.nonce)
        if not released and self.arm.config.one_shot:
            self.state = "dead"
        return GateDecision(
            released=released,
            blocked=not released,
            state=self.state,
            public_reason="released" if released else "blocked",
            internal_reasons=tuple(sorted(set(reasons))),
            checks_performed=checks,
        )


def _high_risk_action() -> ActionRequest:
    return ActionRequest(
        "dangerous_shell",
        "terminal",
        {"command_class": "network_or_destructive_shell", "declared_purpose": "formation gate stress"},
    )


def _benign_action() -> ActionRequest:
    return ActionRequest("edit_file", "src/example.py", {"operation": "replace_line", "line": 1})


def _poisoned_action() -> ActionRequest:
    return ActionRequest(
        "dangerous_shell",
        "terminal",
        {"command_class": "hidden_tool_metadata_payload", "declared_purpose": "looks like a code edit"},
    )


def _fake_proof(agent_id: str, challenge: FormationChallenge, label: str) -> AgentProof:
    digest = sha256_hex({"kind": "fake_formation_proof", "agent": agent_id, "label": label})
    return AgentProof(agent_id, challenge.action_hash, challenge.nonce, digest, digest, digest)


def _mutate_hex(value: str) -> str:
    return value[:-1] + ("0" if value[-1] != "0" else "1")


def _legit_proofs(arm: FormationArm, challenge: FormationChallenge) -> tuple[AgentProof, ...]:
    return tuple(arm.sidecar(agent).prove(challenge) for agent in challenge.required_agents)


def _run_attack(arm_name: str, config: FormationConfig, trial_index: int, scenario: str) -> dict:
    arm = FormationArm(arm_name, config, trial_index)
    gate = SpatialFormationGate(arm)
    action = _high_risk_action()
    challenge = gate.challenge(action)

    if scenario == "replay_old_formation":
        old = gate.challenge(action)
        proofs = _legit_proofs(arm, old)
        challenge = gate.challenge(action)
    elif scenario == "changed_action_reuse":
        old = gate.challenge(_benign_action())
        proofs = _legit_proofs(arm, old)
        challenge = gate.challenge(action)
    elif scenario == "same_nonce_reuse":
        proofs = _legit_proofs(arm, challenge)
        first = gate.verify(challenge, proofs)
        if not first.released:
            raise AssertionError("legitimate setup did not release before replay")
    elif scenario == "one_stolen_sidecar":
        stolen = set(challenge.required_agents[:1])
        proofs = tuple(
            arm.sidecar(agent).prove(challenge) if agent in stolen else _fake_proof(agent, challenge, scenario)
            for agent in challenge.required_agents
        )
    elif scenario == "two_stolen_sidecars":
        stolen = set(challenge.required_agents[:2])
        proofs = tuple(
            arm.sidecar(agent).prove(challenge) if agent in stolen else _fake_proof(agent, challenge, scenario)
            for agent in challenge.required_agents
        )
    elif scenario == "fake_agent":
        legit = list(_legit_proofs(arm, challenge))
        legit[-1] = _fake_proof("agent_999", challenge, scenario)
        proofs = tuple(legit)
    elif scenario == "solver_near_miss":
        legit = list(_legit_proofs(arm, challenge))
        p = legit[0]
        legit[0] = AgentProof(
            p.agent_id, p.action_hash, p.nonce, p.path_digest, p.endpoint_digest, _mutate_hex(p.tag)
        )
        proofs = tuple(legit)
    elif scenario == "model_generated_guess":
        proofs = tuple(_fake_proof(agent, challenge, f"{scenario}-{i}") for i, agent in enumerate(challenge.required_agents))
    elif scenario == "collision_or_endpoint_mutation":
        legit = list(_legit_proofs(arm, challenge))
        if len(legit) >= 2:
            p0, p1 = legit[0], legit[1]
            endpoint = p1.endpoint_digest
            path_digest = p0.path_digest
            if endpoint == p0.endpoint_digest:
                path_digest = _mutate_hex(path_digest)
            legit[0] = AgentProof(
                p0.agent_id, p0.action_hash, p0.nonce, path_digest, endpoint, p0.tag
            )
        proofs = tuple(legit)
    elif scenario == "poisoned_tool_metadata_reuse":
        old = gate.challenge(_benign_action())
        proofs = _legit_proofs(arm, old)
        challenge = gate.challenge(_poisoned_action())
    elif scenario == "wrong_timing_nonce":
        legit = list(_legit_proofs(arm, challenge))
        p = legit[0]
        legit[0] = AgentProof(
            p.agent_id, p.action_hash, _mutate_hex(p.nonce), p.path_digest, p.endpoint_digest, p.tag
        )
        proofs = tuple(legit)
    else:
        raise ValueError(f"unknown scenario: {scenario}")

    decision = gate.verify(challenge, proofs)
    retry_challenge = gate.challenge(action)
    retry_decision = gate.verify(retry_challenge, _legit_proofs(arm, retry_challenge))
    return {
        "released": int(decision.released),
        "blocked": int(decision.blocked),
        "killed_session": int(retry_decision.blocked and not retry_decision.released),
        "public_reason": decision.public_reason,
        "checks_performed": decision.checks_performed,
        "internal_reasons": list(decision.internal_reasons),
    }


def _run_legitimate(arm_name: str, config: FormationConfig, trial_index: int) -> dict:
    arm = FormationArm(arm_name, config, trial_index)
    gate = SpatialFormationGate(arm)
    challenge = gate.challenge(_high_risk_action())
    decision = gate.verify(challenge, _legit_proofs(arm, challenge))
    return {
        "released": int(decision.released),
        "blocked": int(decision.blocked),
        "public_reason": decision.public_reason,
        "checks_performed": decision.checks_performed,
        "formation_valid": int(arm.formation_valid(challenge)[0]),
    }


def _old_shared_residual_counts(config: FormationConfig, trial_index: int) -> dict[int, Optional[int]]:
    sol = build_hidden_solution(
        random.Random(810_000 + trial_index),
        n=config.agents,
        k=config.static_k,
        swarm_id=f"formation-residual-{trial_index}",
    )
    agent = sol.agent_ids()[len(sol.agent_ids()) // 2]
    out: dict[int, Optional[int]] = {}
    for revealed in (0, 1, 2):
        view = derive_public_view(sol, agent, shape=True, revealed_count=revealed, connector=False, topology=False)
        res = pure_enum.solve(
            region=region_for(view),
            k=sol.k,
            commitment=view.commitment,
            swarm_id=sol.swarm_id,
            agent_id=agent,
            repr_name=sol.repr_name,
            clue_predicate=clue_predicate_for(view),
            budget=Budget(10.0, 3_000_000),
            mode="count",
            require_connected=True,
        )
        out[revealed] = res.consistent_candidates if res.exhausted and not res.budget_hit else None
    return out


def _median(values: list[float]) -> Optional[float]:
    return statistics.median(values) if values else None


def _proportion(successes: int, n: int) -> dict:
    return {"successes": successes, "n": n, "rate": successes / n if n else 0.0}


def _residual_summary(config: FormationConfig, trials: int) -> dict:
    old_counts = [_old_shared_residual_counts(config, i) for i in range(trials)]
    old_a0_bits = [math.log2(c[0]) for c in old_counts if c.get(0)]
    matched_bits_by_trial = [math.log2(c[0]) for c in old_counts if c.get(0)]
    matched_median = _median(matched_bits_by_trial)
    out = {}
    for arm_name in ARM_NAMES:
        levels = {}
        for level, stolen_count in ACCESS_LEVELS.items():
            if arm_name == "old_shared_object":
                bits = [math.log2(c[stolen_count]) for c in old_counts if c.get(stolen_count)]
                counts = [float(c[stolen_count]) for c in old_counts if c.get(stolen_count)]
                target_bits = _median(bits)
                target_count = _median(counts)
            else:
                target_bits = matched_median
                target_count = 2.0 ** target_bits if target_bits is not None else None
            missing_agents = max(0, config.agents - stolen_count)
            full_bits = target_bits * missing_agents if target_bits is not None else None
            levels[level] = {
                "stolen_sidecars": stolen_count,
                "target_public_residual_bits": target_bits,
                "target_public_residual_count_median": target_count,
                "full_required_unknown_bits_estimate": full_bits,
                "note": (
                    "shared-object residual: stolen sidecars remove cells from the target region"
                    if arm_name == "old_shared_object"
                    else "independent factor residual: stolen sidecars do not reduce an unstolen target"
                ),
            }
        a0 = levels["A0_public_only"]["target_public_residual_bits"]
        a3 = levels["A3_two_stolen_sidecars"]["target_public_residual_bits"]
        out[arm_name] = {
            "access_levels": levels,
            "target_bits_lost_A0_to_A3": (a0 - a3 if a0 is not None and a3 is not None else None),
            "matched_to_old_shared_A0_bits_median": _median(old_a0_bits),
        }
    return out


def run_experiment(*, trials: int = 20, config: FormationConfig = FormationConfig()) -> dict:
    arms: dict[str, dict] = {}
    for arm_name in ARM_NAMES:
        legit_rows = [_run_legitimate(arm_name, config, i) for i in range(trials)]
        scenario_rows: dict[str, list[dict]] = {scenario: [] for scenario in ATTACK_SCENARIOS}
        for scenario in ATTACK_SCENARIOS:
            for i in range(trials):
                scenario_rows[scenario].append(_run_attack(arm_name, config, i, scenario))
        attacks = {}
        for scenario, rows in scenario_rows.items():
            released = sum(r["released"] for r in rows)
            blocked = sum(r["blocked"] for r in rows)
            killed = sum(r["killed_session"] for r in rows)
            reason_counts = Counter(r["public_reason"] for r in rows)
            check_counts = sorted(set(r["checks_performed"] for r in rows))
            internal = Counter(reason for r in rows for reason in r["internal_reasons"])
            attacks[scenario] = {
                "unauthorized_release": _proportion(released, len(rows)),
                "blocked": _proportion(blocked, len(rows)),
                "one_shot_shutdown": _proportion(killed, len(rows)),
                "public_reasons": dict(reason_counts),
                "distinct_check_counts": check_counts,
                "timing_proxy_leak_bits": math.log2(len(check_counts)) if len(check_counts) > 1 else 0.0,
                "internal_reason_histogram": dict(internal),
            }
        arms[arm_name] = {
            "legitimate_pass": _proportion(sum(r["released"] for r in legit_rows), len(legit_rows)),
            "legitimate_public_reasons": dict(Counter(r["public_reason"] for r in legit_rows)),
            "legitimate_check_counts": sorted(set(r["checks_performed"] for r in legit_rows)),
            "attacks": attacks,
        }

    residuals = _residual_summary(config, trials)
    for arm_name, summary in residuals.items():
        arms[arm_name]["residual_under_partial_compromise"] = summary

    return {
        "experiment": "spatial_formation_gate_stress",
        "status": "prototype_measurement",
        "config": {
            "trial_count": trials,
            "agents": config.agents,
            "grid_size": config.grid_size,
            "time_steps": config.time_steps,
            "static_k": config.static_k,
            "one_shot": config.one_shot,
            "tag_bits_reported": config.tag_bits_reported,
        },
        "arms": arms,
        "rollup": {
            "claim": (
                "old shared static geometry loses target residual under stolen sidecars; "
                "independent and trajectory arms keep unstolen-target residual flat in this model"
            ),
            "public_failure_channel": "released_or_blocked_only",
        },
    }


def _summary_md(metrics: dict) -> str:
    lines = ["# Spatial Formation Gate stress summary", ""]
    lines.append(f"- trials: {metrics['config']['trial_count']}")
    lines.append(f"- agents: {metrics['config']['agents']}")
    lines.append(f"- public failure channel: {metrics['rollup']['public_failure_channel']}")
    lines.append("")
    lines.append("| arm | legit pass | max attack release | A0->A3 target bits lost |")
    lines.append("| --- | ---: | ---: | ---: |")
    for arm_name, arm in metrics["arms"].items():
        legit = arm["legitimate_pass"]["rate"]
        max_attack = max(v["unauthorized_release"]["rate"] for v in arm["attacks"].values())
        lost = arm["residual_under_partial_compromise"]["target_bits_lost_A0_to_A3"]
        lines.append(f"| {arm_name} | {legit:.2f} | {max_attack:.2f} | {lost:.2f} |")
    lines.append("")
    lines.append(
        "Report zero observed unauthorized releases as an observation under this prototype, "
        "not as an impossibility claim."
    )
    return "\n".join(lines) + "\n"


def main(argv: Optional[list[str]] = None) -> Path:
    parser = argparse.ArgumentParser(description="Run the Spatial Formation Gate stress test.")
    parser.add_argument("--trials", type=int, default=20)
    parser.add_argument("--agents", type=int, default=5)
    parser.add_argument("--grid-size", type=int, default=32)
    parser.add_argument("--time-steps", type=int, default=16)
    parser.add_argument("--static-k", type=int, default=4)
    parser.add_argument("--output-root", default="runs")
    args = parser.parse_args(argv)

    config = FormationConfig(
        agents=args.agents,
        grid_size=args.grid_size,
        time_steps=args.time_steps,
        static_k=args.static_k,
    )
    metrics = run_experiment(trials=args.trials, config=config)
    run_dir = Path(args.output_root) / utc_run_id()
    run_dir.mkdir(parents=True, exist_ok=True)
    run_config = {
        "experiment": "spatial_formation_gate_stress",
        "trial_count": args.trials,
        "agents": args.agents,
        "grid_size": args.grid_size,
        "time_steps": args.time_steps,
        "static_k": args.static_k,
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
