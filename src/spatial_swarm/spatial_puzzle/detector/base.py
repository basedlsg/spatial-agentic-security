"""Shared detector contract: identical interface so geometry is the only variable.

A `Submission` carries an `attack_class` label used ONLY for scoring; a detector's
`submit` must never branch on it (the keystone "adversary-uniform" discipline,
enforced by a test). Both detectors make the SAME release/catch decision via the
commitment-backed `SwarmLifecycle`; they differ only in the geometric checks layered
on top and in what their `reason` channel discriminates.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Optional, Protocol

from spatial_swarm.spatial_lab import commit as C
from spatial_swarm.spatial_puzzle.enclave.failure_policy import SwarmLifecycle
from spatial_swarm.spatial_puzzle.generators.visibility import HiddenSolution


@dataclass(frozen=True)
class Submission:
    swarm_id: str
    agent_id: str
    candidate: frozenset
    attack_class: str   # provenance label; SCORING ONLY -- a detector MUST NOT read this


@dataclass(frozen=True)
class DetectionResult:
    released: bool         # commitment opened (ground truth)
    blocked: bool
    flagged: bool          # detector raised an alarm (caught/tampered)
    state: str             # alive / dead
    reason: str            # the response channel (a leak surface)
    reason_bits: float     # bits the reason channel can discriminate among wrong candidates (0 = pass/fail only)
    attribution: Optional[str] = None   # e.g. "decoy_consistent"; never changes the release decision


class Detector(Protocol):
    name: str

    def submit(self, sub: Submission) -> DetectionResult: ...

    def reset(self) -> None: ...


def build_lifecycles(
    sol: HiddenSolution, *, one_shot: bool, strikes: int
) -> dict[str, SwarmLifecycle]:
    """One commitment-opening lifecycle per agent (same construction as the sealed service)."""

    def opener(agent: str) -> Callable[[frozenset], bool]:
        return lambda cand: C.opens(sol.commitments[agent], sol.swarm_id, agent, sol.repr_name, cand)

    return {
        aid: SwarmLifecycle(
            sol.swarm_id,
            opens=opener(aid),
            one_shot=one_shot,
            strikes=strikes,
            sidecars={a2: sol.pieces[a2] for a2 in sol.pieces},
        )
        for aid in sol.agent_ids()
    }
