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
import time
from collections import Counter
from dataclasses import dataclass, replace
from functools import lru_cache
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
    "changed_action_same_nonce_reuse",
    "same_nonce_reuse",
    "one_stolen_sidecar",
    "two_stolen_sidecars",
    "fake_agent",
    "solver_near_miss",
    "path_near_miss_same_endpoint",
    "model_generated_guess",
    "collision_or_endpoint_mutation",
    "poisoned_tool_metadata_reuse",
    "wrong_timing_nonce",
    "coordinator_state_forgery",
)

ABLATION_SCENARIOS = (
    "changed_action_same_nonce_reuse",
    "wrong_timing_nonce",
    "path_near_miss_same_endpoint",
    "collision_or_endpoint_mutation",
)


@dataclass(frozen=True)
class FormationConfig:
    agents: int = 5
    grid_size: int = 32
    time_steps: int = 16
    static_k: int = 4
    tag_bits_reported: int = 128
    one_shot: bool = True
    bind_action: bool = True
    bind_nonce: bool = True
    bind_path_digest: bool = True
    bind_endpoint_digest: bool = True
    check_collisions: bool = True
    check_path_crossing: bool = True
    check_forbidden_region: bool = True
    check_final_formation: bool = True


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
    if action.kind in {"push", "install_package", "credential_read", "dangerous_shell", "delete_file"}:
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


def _formation_offsets(
    agent_count: int,
    template: int,
    grid_size: int,
) -> tuple[tuple[int, int, int], ...]:
    side = 1
    while side**3 < agent_count:
        side += 1
    usable = max(1, grid_size - 4)
    spacing = max(1, usable // max(1, side - 1))
    out = []
    for idx in range(agent_count):
        x = idx % side
        y = (idx // side) % side
        z = idx // (side * side)
        if template % 3 == 0:
            coords = (x * spacing, y * spacing, z * spacing)
        elif template % 3 == 1:
            coords = (y * spacing, z * spacing, x * spacing)
        else:
            coords = (z * spacing, x * spacing, y * spacing)
        out.append(tuple(min(grid_size - 2, c) for c in coords))
    return tuple(out)


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


@lru_cache(maxsize=None)
def _cached_old_solution(agents: int, static_k: int, trial_index: int):
    return build_hidden_solution(
        random.Random(710_000 + trial_index),
        n=agents,
        k=static_k,
        swarm_id=f"formation-old-{trial_index}",
    )


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
            self._old_solution = _cached_old_solution(config.agents, config.static_k, trial_index)
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
        payload = {
            "kind": "formation_gate_proof",
            "arm": self.name,
            "agent": agent_id,
        }
        if self.config.bind_action:
            payload["action_hash"] = challenge.action_hash
        if self.config.bind_nonce:
            payload["nonce"] = challenge.nonce
        if self.config.bind_path_digest:
            payload["path_digest"] = trace.path_digest
        if self.config.bind_endpoint_digest:
            payload["endpoint_digest"] = trace.endpoint_digest
        return _hmac_hex(self._agent_secrets[agent_id], payload)

    def formation_valid(self, challenge: FormationChallenge) -> tuple[bool, tuple[str, ...]]:
        if self.name != "coordinated_formation":
            return True, ()
        traces = {agent: self.expected_trace(agent, challenge) for agent in challenge.required_agents}
        reasons: list[str] = []
        paths = [trace.path for trace in traces.values()]
        if any(len(path) != self.config.time_steps for path in paths):
            reasons.append("wrong_path_length")
        if self.config.check_collisions:
            for t in range(self.config.time_steps):
                occupied = [path[t] for path in paths if len(path) > t]
                if len(occupied) != len(set(occupied)):
                    reasons.append("collision")
                    break
        if self.config.check_path_crossing:
            for t in range(self.config.time_steps - 1):
                edges = [((path[t], path[t + 1])) for path in paths]
                edge_set = set(edges)
                swapped = any((b, a) in edge_set for a, b in edge_set if a != b)
                if swapped:
                    reasons.append("path_crossing")
                    break
        if self.config.check_forbidden_region:
            forbidden = self._forbidden_points(challenge)
            if any(point in forbidden for path in paths for point in path):
                reasons.append("forbidden_region")
        endpoints = tuple(path[-1] for path in paths)
        if self.config.check_collisions and len(endpoints) != len(set(endpoints)):
            reasons.append("endpoint_collision")
        if self.config.check_final_formation and not self._endpoints_match_template(challenge, endpoints):
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
        endpoint = self._formation_endpoint(agent_id, challenge)
        path = []
        for t in range(self.config.time_steps):
            shift = self.config.time_steps - 1 - t
            path.append(((endpoint[0] + shift) % self.config.grid_size, endpoint[1], endpoint[2]))
        return tuple(path)

    def _formation_endpoint(self, agent_id: str, challenge: FormationChallenge) -> tuple[int, int, int]:
        idx = self.agent_ids.index(agent_id)
        digest = _secret("formation_template", self.trial_index, challenge.action_hash, challenge.nonce)
        template = digest[0] % 3
        max_anchor = 2
        anchor = (
            2 + digest[1] % max_anchor,
            2 + digest[2] % max_anchor,
            2 + digest[3] % max_anchor,
        )
        off = _formation_offsets(self.config.agents, template, self.config.grid_size)[idx]
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
            if self.arm.config.bind_action and proof.action_hash != challenge.action_hash:
                reasons.append("wrong_action")
            if self.arm.config.bind_nonce and proof.nonce != challenge.nonce:
                reasons.append("wrong_nonce")
            if self.arm.config.bind_path_digest and proof.path_digest != trace.path_digest:
                reasons.append("wrong_path_digest")
            if self.arm.config.bind_endpoint_digest and proof.endpoint_digest != trace.endpoint_digest:
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


def _action_suite() -> tuple[ActionRequest, ...]:
    return (
        ActionRequest("read_file", "src/example.py", {"operation": "summarize"}),
        ActionRequest("edit_file", "src/example.py", {"operation": "replace_line", "line": 1}),
        ActionRequest("run_command", "pytest", {"command_class": "local_test"}),
        ActionRequest("install_package", "package_manager", {"package": "example-dependency"}),
        ActionRequest("delete_file", "tmp/output.log", {"operation": "delete"}),
        ActionRequest("push", "origin", {"branch": "codex/mesh-nebula-core"}),
        ActionRequest("credential_read", "env", {"name": "API_TOKEN"}),
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
    elif scenario == "changed_action_same_nonce_reuse":
        old = gate.challenge(_benign_action())
        proofs = _legit_proofs(arm, old)
        challenge = FormationChallenge(
            arm=old.arm,
            action_hash=action.action_hash(),
            nonce=old.nonce,
            risk=_risk_for_action(action),
            required_agents=old.required_agents,
        )
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
    elif scenario == "path_near_miss_same_endpoint":
        legit = list(_legit_proofs(arm, challenge))
        p = legit[0]
        legit[0] = AgentProof(
            p.agent_id, p.action_hash, p.nonce, _mutate_hex(p.path_digest), p.endpoint_digest, p.tag
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
    elif scenario == "coordinator_state_forgery":
        proofs = _legit_proofs(arm, challenge)
        challenge = FormationChallenge(
            arm=challenge.arm,
            action_hash=challenge.action_hash,
            nonce=_mutate_hex(challenge.nonce),
            risk=challenge.risk,
            required_agents=tuple(reversed(challenge.required_agents)),
        )
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


def _action_binding_suite(config: FormationConfig, trials: int) -> dict:
    out = {}
    for action in _action_suite():
        legit, changed_reuse, same_nonce_reuse = 0, 0, 0
        risks = []
        required_counts = []
        for trial_index in range(trials):
            arm = FormationArm("coordinated_formation", config, trial_index)
            gate = SpatialFormationGate(arm)
            challenge = gate.challenge(action)
            risks.append(challenge.risk)
            required_counts.append(len(challenge.required_agents))
            decision = gate.verify(challenge, _legit_proofs(arm, challenge))
            legit += int(decision.released)

            arm2 = FormationArm("coordinated_formation", config, 50_000 + trial_index)
            gate2 = SpatialFormationGate(arm2)
            source_action = _benign_action() if action.kind == _action_suite()[0].kind else _action_suite()[0]
            old = gate2.challenge(source_action)
            proofs = _legit_proofs(arm2, old)
            changed = gate2.challenge(action)
            changed_reuse += int(gate2.verify(changed, proofs).released)

            arm3 = FormationArm("coordinated_formation", config, 60_000 + trial_index)
            gate3 = SpatialFormationGate(arm3)
            old_same_nonce = gate3.challenge(source_action)
            proofs_same_nonce = _legit_proofs(arm3, old_same_nonce)
            forged = FormationChallenge(
                arm=old_same_nonce.arm,
                action_hash=action.action_hash(),
                nonce=old_same_nonce.nonce,
                risk=_risk_for_action(action),
                required_agents=old_same_nonce.required_agents,
            )
            same_nonce_reuse += int(gate3.verify(forged, proofs_same_nonce).released)
        out[action.kind] = {
            "risk": Counter(risks).most_common(1)[0][0],
            "required_agents_median": _median([float(v) for v in required_counts]),
            "legitimate_pass": _proportion(legit, trials),
            "changed_action_reuse_release": _proportion(changed_reuse, trials),
            "changed_action_same_nonce_reuse_release": _proportion(same_nonce_reuse, trials),
        }
    return out


def _ablation_configs(config: FormationConfig) -> dict[str, FormationConfig]:
    return {
        "full_geometry": config,
        "no_action_binding": replace(config, bind_action=False),
        "no_nonce_binding": replace(config, bind_nonce=False),
        "no_path_binding": replace(config, bind_path_digest=False),
        "no_endpoint_binding": replace(config, bind_endpoint_digest=False),
        "no_geometry_binding": replace(
            config,
            bind_path_digest=False,
            bind_endpoint_digest=False,
            check_collisions=False,
            check_path_crossing=False,
            check_forbidden_region=False,
            check_final_formation=False,
        ),
        "no_action_or_geometry_binding": replace(
            config,
            bind_action=False,
            bind_path_digest=False,
            bind_endpoint_digest=False,
            check_collisions=False,
            check_path_crossing=False,
            check_forbidden_region=False,
            check_final_formation=False,
        ),
    }


def _ablation_suite(config: FormationConfig, trials: int) -> dict:
    out = {}
    for ablation, cfg in _ablation_configs(config).items():
        attacks = {}
        for scenario in ABLATION_SCENARIOS:
            rows = [_run_attack("coordinated_formation", cfg, 70_000 + i, scenario) for i in range(trials)]
            attacks[scenario] = {
                "release": _proportion(sum(r["released"] for r in rows), len(rows)),
                "blocked": _proportion(sum(r["blocked"] for r in rows), len(rows)),
                "dominant_internal_reasons": dict(Counter(reason for r in rows for reason in r["internal_reasons"])),
            }
        out[ablation] = attacks
    return out


def _analysis_mode_suite(config: FormationConfig, trials: int) -> dict:
    cfg = replace(config, one_shot=False)
    out = {}
    for scenario in ATTACK_SCENARIOS:
        rows = [_run_attack("coordinated_formation", cfg, 80_000 + i, scenario) for i in range(trials)]
        out[scenario] = {
            "release": _proportion(sum(r["released"] for r in rows), len(rows)),
            "blocked": _proportion(sum(r["blocked"] for r in rows), len(rows)),
            "session_survived_after_block": _proportion(
                sum(1 - r["killed_session"] for r in rows), len(rows)
            ),
            "internal_reason_histogram": dict(Counter(reason for r in rows for reason in r["internal_reasons"])),
        }
    return out


def _timing_probe(config: FormationConfig, trials: int) -> dict:
    out = {}
    for scenario in ATTACK_SCENARIOS:
        elapsed_ms = []
        checks = []
        for trial_index in range(trials):
            start = time.perf_counter_ns()
            row = _run_attack("coordinated_formation", config, 90_000 + trial_index, scenario)
            elapsed_ms.append((time.perf_counter_ns() - start) / 1_000_000)
            checks.append(float(row["checks_performed"]))
        out[scenario] = {
            "elapsed_ms": _summary_values(elapsed_ms),
            "checks_performed": _summary_values(checks),
            "timing_proxy_leak_bits": math.log2(len(set(checks))) if len(set(checks)) > 1 else 0.0,
        }
    return out


def _sweep_agents(agent_counts: tuple[int, ...], trials: int, config: FormationConfig) -> dict:
    out = {}
    for agents in agent_counts:
        cfg = replace(config, agents=agents)
        legit_rows = [_run_legitimate("coordinated_formation", cfg, i) for i in range(trials)]
        attack_rows = {
            scenario: [_run_attack("coordinated_formation", cfg, i, scenario) for i in range(trials)]
            for scenario in ATTACK_SCENARIOS
        }
        out[str(agents)] = {
            "legitimate_pass": _proportion(sum(r["released"] for r in legit_rows), len(legit_rows)),
            "max_attack_release": max(
                _proportion(sum(r["released"] for r in rows), len(rows))["rate"]
                for rows in attack_rows.values()
            ),
            "required_agents_high_risk": agents,
        }
    return out


def _cheap_attack_stress(config: FormationConfig, trials: int) -> dict:
    if trials <= 0:
        return {}
    out = {}
    for scenario in ATTACK_SCENARIOS:
        released = 0
        blocked = 0
        killed = 0
        public_reasons = Counter()
        check_counts = set()
        internal = Counter()
        for trial_index in range(trials):
            row = _run_attack("coordinated_formation", config, 100_000 + trial_index, scenario)
            released += row["released"]
            blocked += row["blocked"]
            killed += row["killed_session"]
            public_reasons[row["public_reason"]] += 1
            check_counts.add(row["checks_performed"])
            internal.update(row["internal_reasons"])
        out[scenario] = {
            "unauthorized_release": _proportion(released, trials),
            "blocked": _proportion(blocked, trials),
            "one_shot_shutdown": _proportion(killed, trials),
            "public_reasons": dict(public_reasons),
            "distinct_check_counts": sorted(check_counts),
            "timing_proxy_leak_bits": math.log2(len(check_counts)) if len(check_counts) > 1 else 0.0,
            "internal_reason_histogram": dict(internal),
        }
    return out


def _old_shared_residual_counts(config: FormationConfig, trial_index: int) -> dict[int, Optional[int]]:
    sol = build_hidden_solution(
        random.Random(810_000 + trial_index),
        n=config.agents,
        k=config.static_k,
        swarm_id=f"formation-residual-{trial_index}",
    )
    agent = sol.agent_ids()[len(sol.agent_ids()) // 2]
    return _old_shared_counts_for_agent(sol, agent)


def _old_shared_counts_for_agent(sol, agent: str) -> dict[int, Optional[int]]:
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


def _old_shared_target_selection_summary(config: FormationConfig, trials: int) -> dict:
    sampled_trials = min(trials, 100)
    losses_by_role: dict[str, list[float]] = {agent: [] for agent in _agent_ids(config.agents)}
    all_losses: list[float] = []
    for trial_index in range(sampled_trials):
        sol = build_hidden_solution(
            random.Random(910_000 + trial_index),
            n=config.agents,
            k=config.static_k,
            swarm_id=f"formation-targets-{trial_index}",
        )
        for agent in sol.agent_ids():
            counts = _old_shared_counts_for_agent(sol, agent)
            if counts.get(0) and counts.get(2):
                loss = math.log2(counts[0]) - math.log2(counts[2])
                losses_by_role[agent].append(loss)
                all_losses.append(loss)
    role_medians = {
        agent: _median(values)
        for agent, values in losses_by_role.items()
        if values
    }
    ordered = sorted((loss, agent) for agent, loss in role_medians.items() if loss is not None)
    return {
        "sampled_trials": sampled_trials,
        "easiest_agent_by_A0_to_A3_loss": (
            {"agent": ordered[-1][1], "bits_lost": ordered[-1][0]} if ordered else None
        ),
        "hardest_agent_by_A0_to_A3_loss": (
            {"agent": ordered[0][1], "bits_lost": ordered[0][0]} if ordered else None
        ),
        "median_agent_bits_lost": _median([loss for loss in role_medians.values() if loss is not None]),
        "all_agent_loss_summary": _summary_values(all_losses),
        "per_agent_median_bits_lost": role_medians,
    }


def _median(values: list[float]) -> Optional[float]:
    return statistics.median(values) if values else None


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


def _proportion(successes: int, n: int) -> dict:
    return {"successes": successes, "n": n, "rate": successes / n if n else 0.0}


def _residual_summary(config: FormationConfig, trials: int) -> dict:
    old_counts = [_old_shared_residual_counts(config, i) for i in range(trials)]
    old_a0_bits = [math.log2(c[0]) for c in old_counts if c.get(0)]
    matched_bits_by_trial = [math.log2(c[0]) for c in old_counts if c.get(0)]
    matched_median = _median(matched_bits_by_trial)
    target_selection = _old_shared_target_selection_summary(config, trials)
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
        if arm_name == "old_shared_object":
            out[arm_name]["target_selection"] = target_selection
    return out


def run_experiment(
    *,
    trials: int = 20,
    config: FormationConfig = FormationConfig(),
    diagnostic_trials: Optional[int] = None,
    timing_trials: Optional[int] = None,
    sweep_agent_counts: tuple[int, ...] = (),
    sweep_trials: int = 50,
    cheap_attack_trials: int = 0,
) -> dict:
    diagnostic_n = diagnostic_trials if diagnostic_trials is not None else min(trials, 200)
    timing_n = timing_trials if timing_trials is not None else min(trials, 100)
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
            "diagnostic_trial_count": diagnostic_n,
            "timing_trial_count": timing_n,
            "cheap_attack_trial_count": cheap_attack_trials,
            "agents": config.agents,
            "grid_size": config.grid_size,
            "time_steps": config.time_steps,
            "static_k": config.static_k,
            "one_shot": config.one_shot,
            "tag_bits_reported": config.tag_bits_reported,
            "binding": {
                "action": config.bind_action,
                "nonce": config.bind_nonce,
                "path_digest": config.bind_path_digest,
                "endpoint_digest": config.bind_endpoint_digest,
            },
            "geometry_checks": {
                "collisions": config.check_collisions,
                "path_crossing": config.check_path_crossing,
                "forbidden_region": config.check_forbidden_region,
                "final_formation": config.check_final_formation,
            },
        },
        "arms": arms,
        "action_binding": _action_binding_suite(config, diagnostic_n),
        "ablations": _ablation_suite(config, diagnostic_n),
        "analysis_mode_no_shutdown": _analysis_mode_suite(config, diagnostic_n),
        "timing_probe": _timing_probe(config, timing_n),
        "agent_sweep": _sweep_agents(sweep_agent_counts, sweep_trials, config) if sweep_agent_counts else {},
        "cheap_attack_stress": _cheap_attack_stress(config, cheap_attack_trials),
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
    lines.append(f"- diagnostic_trials: {metrics['config']['diagnostic_trial_count']}")
    lines.append(f"- timing_trials: {metrics['config']['timing_trial_count']}")
    lines.append(f"- cheap_attack_trials: {metrics['config']['cheap_attack_trial_count']}")
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
    lines.append("| ablation | max release in ablation scenarios |")
    lines.append("| --- | ---: |")
    for name, attacks in metrics["ablations"].items():
        max_release = max(a["release"]["rate"] for a in attacks.values())
        lines.append(f"| {name} | {max_release:.2f} |")
    if metrics.get("agent_sweep"):
        lines.append("")
        lines.append("| coordinated agents | legit pass | max attack release |")
        lines.append("| ---: | ---: | ---: |")
        for agents, row in metrics["agent_sweep"].items():
            lines.append(
                f"| {agents} | {row['legitimate_pass']['rate']:.2f} | {row['max_attack_release']:.2f} |"
            )
    if metrics.get("cheap_attack_stress"):
        max_release = max(
            row["unauthorized_release"]["rate"] for row in metrics["cheap_attack_stress"].values()
        )
        lines.append("")
        lines.append(
            f"Cheap attack stress max release: {max_release:.2f} "
            f"over {metrics['config']['cheap_attack_trial_count']} trials per scenario."
        )
    lines.append("")
    lines.append(
        "Report zero observed unauthorized releases as an observation under this prototype, "
        "not as an impossibility claim."
    )
    return "\n".join(lines) + "\n"


def main(argv: Optional[list[str]] = None) -> Path:
    parser = argparse.ArgumentParser(description="Run the Spatial Formation Gate stress test.")
    parser.add_argument("--trials", type=int, default=20)
    parser.add_argument("--diagnostic-trials", type=int, default=None)
    parser.add_argument("--timing-trials", type=int, default=None)
    parser.add_argument("--sweep-agents", default="")
    parser.add_argument("--sweep-trials", type=int, default=50)
    parser.add_argument("--cheap-attack-trials", type=int, default=0)
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
    sweep_agent_counts = tuple(
        int(part) for part in args.sweep_agents.split(",") if part.strip()
    )
    metrics = run_experiment(
        trials=args.trials,
        config=config,
        diagnostic_trials=args.diagnostic_trials,
        timing_trials=args.timing_trials,
        sweep_agent_counts=sweep_agent_counts,
        sweep_trials=args.sweep_trials,
        cheap_attack_trials=args.cheap_attack_trials,
    )
    run_dir = Path(args.output_root) / utc_run_id()
    run_dir.mkdir(parents=True, exist_ok=True)
    run_config = {
        "experiment": "spatial_formation_gate_stress",
        "trial_count": args.trials,
        "diagnostic_trials": args.diagnostic_trials,
        "timing_trials": args.timing_trials,
        "sweep_agents": list(sweep_agent_counts),
        "sweep_trials": args.sweep_trials,
        "cheap_attack_trials": args.cheap_attack_trials,
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
