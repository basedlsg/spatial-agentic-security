"""In-process sealed service for the spatial-puzzle swarm.

API: create_swarm, issue_agent_package, verify_message, destroy_swarm, attest,
public_metadata. The seed and full-puzzle scratch are dropped after creation; the
service retains only commitments + per-agent pieces + per-agent one-shot lifecycles.
The host attacker may steal ONE agent's package (the modeled partial-compromise /
stolen-sidecar vector) but never the seed, the full assembled object, all pieces at
once, or any debug dump; verify_message enforces one-shot; destroy zeroizes.

Software-level locally (testable now); hardware sealing/attestation need SGX (stub).
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Optional

from spatial_swarm.spatial_lab import commit as C
from spatial_swarm.spatial_puzzle.enclave.attestation import Attestation, attest
from spatial_swarm.spatial_puzzle.enclave.failure_policy import SwarmLifecycle, SwarmState
from spatial_swarm.spatial_puzzle.enclave.zeroize import zeroize_mapping
from spatial_swarm.spatial_puzzle.generators.build import build_hidden_solution


@dataclass(frozen=True)
class AgentPackage:
    agent_id: str
    piece: frozenset            # the agent's own secret (legitimate channel / stolen-sidecar vector)
    commitment: str


@dataclass(frozen=True)
class PublicMetadata:
    swarm_id: str
    commitments: dict[str, str]
    state: str
    outer_shape: Optional[list]   # only if the deployment opts to publish it


@dataclass(frozen=True)
class VerifyResult:
    released: bool
    blocked: bool
    reason: str
    state: str


# The only operations the host may invoke (enforced by the process host).
ALLOWED_OPS = ("create_swarm", "issue_agent_package", "verify_message", "destroy_swarm", "attest", "public_metadata", "health_check")


class SealedService:
    def __init__(self, one_shot: bool = True, expose_outer_shape: bool = False) -> None:
        self.one_shot = one_shot
        self.expose_outer_shape = expose_outer_shape
        self._swarms: dict[str, dict] = {}

    def create_swarm(self, *, n: int, k: int, seed: int, alphabet_size: int = 4) -> PublicMetadata:
        swarm_id = f"swarm-{seed}"
        sol = build_hidden_solution(
            random.Random(seed), n=n, k=k, swarm_id=swarm_id, alphabet_size=alphabet_size
        )
        lifecycles = {
            aid: SwarmLifecycle(
                swarm_id,
                opens=(lambda cand, a=aid: C.opens(sol.commitments[a], swarm_id, a, sol.repr_name, cand)),
                one_shot=self.one_shot,
                sidecars={a2: sol.pieces[a2] for a2 in sol.pieces},
            )
            for aid in sol.agent_ids()
        }
        # seed / full-puzzle scratch are not retained; only what is below is kept.
        self._swarms[swarm_id] = {"sol": sol, "lifecycles": lifecycles, "state": SwarmState.ALIVE}
        return self.public_metadata(swarm_id)

    def issue_agent_package(self, swarm_id: str, agent_id: str) -> AgentPackage:
        sol = self._swarms[swarm_id]["sol"]
        return AgentPackage(agent_id, sol.pieces[agent_id], sol.commitments[agent_id])

    def verify_message(self, swarm_id: str, agent_id: str, candidate) -> VerifyResult:
        entry = self._swarms[swarm_id]
        out = entry["lifecycles"][agent_id].submit_proof(frozenset(candidate))
        if out.state is SwarmState.DEAD:
            entry["state"] = SwarmState.DEAD
        return VerifyResult(out.released, out.blocked, out.reason, out.state.value)

    def destroy_swarm(self, swarm_id: str, reason: str = "requested") -> None:
        entry = self._swarms.get(swarm_id)
        if not entry:
            return
        for lc in entry["lifecycles"].values():
            zeroize_mapping(lc.sidecars)
        entry["state"] = SwarmState.DEAD
        entry["sol"] = None
        entry["lifecycles"] = {}

    def attest(self) -> Attestation:
        return attest()

    def public_metadata(self, swarm_id: str) -> PublicMetadata:
        entry = self._swarms[swarm_id]
        sol = entry["sol"]
        commitments = dict(sol.commitments) if sol else {}
        outer = sorted(list(c) for c in sol.target) if (sol and self.expose_outer_shape) else None
        return PublicMetadata(swarm_id, commitments, entry["state"].value, outer)

    def health_check(self) -> dict:
        return {"status": "ok", "swarms": len(self._swarms)}
