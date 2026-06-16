"""Three systems for the partial-compromise stress test, at matched second-factor entropy.

All three keep a random high-entropy secret as the LOCK (frozen UCOG commitment). They
differ only in the SECOND FACTOR layered on top:

  random_only : no second factor (literal Baseline A; lock-only sanity).
  random_plus : a matched-entropy RANDOM second factor (the fairness control).
  spatial     : a matched-entropy hidden-3D SPATIAL second factor (System B).

The lock is assumed to hold under every access level A0..A8 (none give the target's own
secret), so the measured quantity is the SECOND FACTOR's residual / one-shot success /
leakage under partial compromise. A random second factor is independent of other agents
(stolen neighbors reveal nothing); a spatial second factor is correlated (stolen
neighbors remove cells from the target's region). Matching entropy isolates spatial-ness
from merely "extra committed material".
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Callable, Optional

from spatial_swarm.spatial_lab import commit as C
from spatial_swarm.spatial_lab.entropy import (
    EntropyAccount,
    bands_overlap,
    log2_comb,
    smallest_alphabet_for_bits,
)
from spatial_swarm.spatial_lab.representations import build_swarm, commitment_only_entropy
from spatial_swarm.spatial_lab.solvers.base import Budget
from spatial_swarm.spatial_puzzle.generators.build import build_hidden_solution
from spatial_swarm.spatial_puzzle.generators.visibility import HiddenSolution
from spatial_swarm.spatial_puzzle.solvers import pure_enum

ARMS = ("random_only", "random_plus", "spatial")
_LOCK_BITS = 64.0  # representative random-lock entropy for the lock-only sanity arm


@dataclass
class Arm:
    kind: str
    n: int
    k: int
    swarm_id: str
    target_agent: str
    opener: Callable[[frozenset], bool]
    second_factor_bits: float
    entropy_basis: str
    match_is_upper_bound: bool
    repr_name: str
    true_piece: frozenset
    neighbors: dict = field(default_factory=dict)   # other agents' second-factor pieces
    sol: Optional[HiddenSolution] = None            # spatial only
    region: Optional[frozenset] = None              # spatial only: the outer shape
    alphabet_m: Optional[int] = None                # random only: alphabet size
    factor_count: Optional[int] = None              # spatial: #connected k-subsets (None if not enumerated)

    def entropy_account(self) -> EntropyAccount:
        return EntropyAccount(self.kind, self.second_factor_bits, self.entropy_basis, self.match_is_upper_bound)


def build_spatial_arm(rng: random.Random, *, n: int, k: int, swarm_id: str,
                      budget: tuple[float, int] = (20.0, 5_000_000)) -> Arm:
    sol = build_hidden_solution(rng, n=n, k=k, swarm_id=swarm_id)
    agent = sol.agent_ids()[len(sol.agent_ids()) // 2]
    res = pure_enum.solve(
        region=sol.target, k=k, commitment=sol.commitments[agent], swarm_id=sol.swarm_id,
        agent_id=agent, repr_name=sol.repr_name, budget=Budget(*budget), mode="count",
        require_connected=True,
    )
    if res.exhausted and not res.budget_hit and res.consistent_candidates:
        count = res.consistent_candidates
        bits = math.log2(count)
        basis = f"log2(connected_k_subsets={count})"
        ub = False
    else:
        acct = commitment_only_entropy("R2", n, k, {})
        count, bits, basis, ub = None, acct.secret_space_bits, acct.basis, True

    def opener(cand, a=agent):
        return C.opens(sol.commitments[a], sol.swarm_id, a, sol.repr_name, cand)

    return Arm(
        kind="spatial", n=n, k=k, swarm_id=swarm_id, target_agent=agent, opener=opener,
        second_factor_bits=bits, entropy_basis=basis, match_is_upper_bound=ub,
        repr_name=sol.repr_name, true_piece=sol.pieces[agent],
        neighbors={a: p for a, p in sol.pieces.items() if a != agent},
        sol=sol, region=sol.target, factor_count=count,
    )


def _build_random_arm(kind: str, rng: random.Random, *, n: int, k: int, swarm_id: str,
                      match_bits: float) -> Arm:
    m = smallest_alphabet_for_bits(k, match_bits)
    sw = build_swarm("R0", rng, n, k, {"m": m}, swarm_id)
    agent = sw.agent_ids()[len(sw.agent_ids()) // 2]
    bits = log2_comb(m, k)

    def opener(cand, a=agent):
        return C.opens(sw.commitments[a], swarm_id, a, "R0", cand)

    return Arm(
        kind=kind, n=n, k=k, swarm_id=swarm_id, target_agent=agent, opener=opener,
        second_factor_bits=bits, entropy_basis=f"C(M={m},k={k})", match_is_upper_bound=False,
        repr_name="R0", true_piece=sw.pieces[agent],
        neighbors={a: p for a, p in sw.pieces.items() if a != agent}, alphabet_m=m,
    )


def build_random_plus_arm(rng: random.Random, *, n: int, k: int, swarm_id: str, match_bits: float) -> Arm:
    """Random second factor matched to the spatial arm's entropy (the fairness control)."""

    return _build_random_arm("random_plus", rng, n=n, k=k, swarm_id=swarm_id, match_bits=match_bits)


def build_random_only_arm(rng: random.Random, *, n: int, k: int, swarm_id: str) -> Arm:
    """Lock-only baseline: a single random high-entropy secret, no second factor."""

    return _build_random_arm("random_only", rng, n=n, k=k, swarm_id=swarm_id, match_bits=_LOCK_BITS)


def build_arms(rng: random.Random, *, n: int, k: int, swarm_id: str,
               budget: tuple[float, int] = (20.0, 5_000_000)) -> dict:
    """Build all three arms for one seed; random_plus is matched to the spatial factor's entropy."""

    spatial = build_spatial_arm(rng, n=n, k=k, swarm_id=f"{swarm_id}-spatial", budget=budget)
    random_plus = build_random_plus_arm(rng, n=n, k=k, swarm_id=f"{swarm_id}-rplus",
                                        match_bits=spatial.second_factor_bits)
    random_only = build_random_only_arm(rng, n=n, k=k, swarm_id=f"{swarm_id}-ronly")
    match = {
        "spatial_bits": spatial.second_factor_bits,
        "random_plus_bits": random_plus.second_factor_bits,
        "match_gap_bits": abs(spatial.second_factor_bits - random_plus.second_factor_bits),
        "bands_overlap_0p5": bands_overlap([spatial.entropy_account(), random_plus.entropy_account()], 0.5),
        "spatial_is_upper_bound": spatial.match_is_upper_bound,
    }
    return {"random_only": random_only, "random_plus": random_plus, "spatial": spatial, "entropy_match": match}
