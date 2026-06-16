"""Anti-leak spatial generator: keep the target ambiguous under stolen neighbors.

The prior partial-compromise finding showed the existing spatial generator produces
correlated pieces, so stealing neighbors collapses the target's residual. This module
scores a candidate puzzle by its WORST-CASE residual after one/two neighbors are stolen
(the attacker picks which to steal) and selects, from a pool of candidates, the one that
stays most ambiguous under that compromise. It is compared against the old A0-filtered
generator and a matched-entropy random factor.

Residual = number of connected k-subsets of (target outer shape minus stolen-neighbor
cells); hidden connectors/topology are never published, so the attacker prunes only with
shape + stolen pieces.
"""

from __future__ import annotations

import itertools
import math
import random
from dataclasses import dataclass
from typing import Optional

from spatial_swarm.spatial_lab.solvers.base import Budget
from spatial_swarm.spatial_puzzle.generators.build import build_hidden_solution
from spatial_swarm.spatial_puzzle.generators.visibility import HiddenSolution
from spatial_swarm.spatial_puzzle.solvers import cheap_attacks, graph_iso, pure_enum

_A0_AMBIGUITY_TARGET = 4


def _residual(sol: HiddenSolution, agent: str, revealed_agents, budget: tuple) -> Optional[int]:
    revealed = frozenset().union(*[sol.pieces[a] for a in revealed_agents]) if revealed_agents else frozenset()
    region = frozenset(sol.target) - revealed
    if len(region) < sol.k:
        return None
    r = pure_enum.solve(
        region=region, k=sol.k, commitment=sol.commitments[agent], swarm_id=sol.swarm_id,
        agent_id=agent, repr_name=sol.repr_name, budget=Budget(*budget), mode="count",
        require_connected=True,
    )
    return r.consistent_candidates if (r.exhausted and not r.budget_hit) else None


def _worst_case(sol: HiddenSolution, agent: str, others: list, steal: int, budget: tuple):
    """Minimum residual over every choice of `steal` neighbors the attacker could take."""

    vals = []
    for combo in itertools.combinations(others, steal):
        v = _residual(sol, agent, combo, budget)
        if v is None:
            return None, False
        vals.append(v)
    return (min(vals) if vals else None), True


@dataclass
class CandidateScore:
    sol: HiddenSolution
    agent: str
    a0: Optional[int]
    worst_a2: Optional[int]
    worst_a3: Optional[int]
    neighbor_copy: bool
    congruent: bool
    enumerated: bool

    @property
    def a0_ok(self) -> bool:
        # the old generator's acceptance: ambiguous at A0, no neighbor-copy, no congruent neighbor
        return bool(self.enumerated and self.a0 and self.a0 >= _A0_AMBIGUITY_TARGET
                    and not self.neighbor_copy and not self.congruent)

    @property
    def anti_leak_score(self) -> float:
        # bottleneck under partial compromise: keep BOTH worst-A2 and worst-A3 high
        if not self.enumerated or self.worst_a2 is None or self.worst_a3 is None:
            return -1.0
        return float(min(self.worst_a2, self.worst_a3))


def score_candidate(sol: HiddenSolution, *, budget: tuple) -> CandidateScore:
    agent = sol.agent_ids()[len(sol.agent_ids()) // 2]
    others = [a for a in sol.agent_ids() if a != agent]
    a0 = _residual(sol, agent, [], budget)
    worst_a2, ok2 = _worst_case(sol, agent, others, 1, budget)
    worst_a3, ok3 = _worst_case(sol, agent, others, 2, budget)
    neighbor_copy = cheap_attacks.neighbor_copy(
        commitment=sol.commitments[agent], swarm_id=sol.swarm_id, agent_id=agent,
        repr_name=sol.repr_name, other_pieces=[sol.pieces[a] for a in others],
    ).found
    congruent = graph_iso.congruence_leak(sol.pieces[agent], [sol.pieces[a] for a in others])
    enumerated = bool(a0 is not None and ok2 and ok3)
    return CandidateScore(sol, agent, a0, worst_a2, worst_a3, neighbor_copy, congruent, enumerated)


def generate_pool(rng: random.Random, *, n: int, k: int, pool: int, budget: tuple,
                  seed_base: int) -> list:
    scores = []
    s = seed_base
    while len(scores) < pool and s < seed_base + pool * 8:
        try:
            sol = build_hidden_solution(rng, n=n, k=k, swarm_id=f"al-{s}")
        except RuntimeError:
            s += 1
            continue
        scores.append(score_candidate(sol, budget=budget))
        s += 1
    return scores


def select_old(pool: list) -> Optional[CandidateScore]:
    """Old spatial generator: the first candidate that passes the A0-only acceptance."""

    for c in pool:
        if c.a0_ok:
            return c
    return next((c for c in pool if c.enumerated), None)


def select_anti_leak(pool: list) -> Optional[CandidateScore]:
    """Anti-leak generator: among A0-acceptable candidates, the highest worst-case A2/A3."""

    ok = [c for c in pool if c.a0_ok]
    candidates = ok or [c for c in pool if c.enumerated]
    if not candidates:
        return None
    return max(candidates, key=lambda c: (c.anti_leak_score, c.worst_a2 or 0, c.a0 or 0))


def threshold_yield(pool: list, *, target_a2: int, target_a3: int) -> float:
    """Fraction of the A0-acceptable pool that also stays ambiguous under A2 and A3."""

    ok = [c for c in pool if c.a0_ok]
    if not ok:
        return 0.0
    passed = sum(1 for c in ok if (c.worst_a2 or 0) >= target_a2 and (c.worst_a3 or 0) >= target_a3)
    return passed / len(ok)


def matched_random_bits(a0_residual: int) -> float:
    """Entropy (bits) of a random factor matched to the spatial A0 residual."""

    return math.log2(a0_residual) if a0_residual and a0_residual > 0 else 0.0
