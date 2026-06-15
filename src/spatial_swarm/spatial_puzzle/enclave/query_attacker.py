"""Attacker query models under retries-allowed vs one-shot, over a residual set of size R.

Findings this is built to measure (honestly, for both random ceiling and spatial residual):
- blind one-shot: a single proof guess succeeds with probability 1/R, then the swarm
  is destroyed -> larger R (max-entropy random) is SAFER.
- candidate-elimination with retries: recovers in <= R proof submissions.
- binary-search via a fit/no-fit ORACLE: recovers in ~log2(R) NON-destructive oracle
  queries plus one proof -> a side-oracle defeats one-shot regardless of secret format.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass
from typing import Optional

from spatial_swarm.experiments.stats import clopper_pearson


@dataclass(frozen=True)
class QueryRun:
    strategy: str
    retries_allowed: bool
    queries_before_recovery: Optional[int]
    recovered: bool
    destroyed: bool


def blind_one_shot(residual_size: int, rng: random.Random) -> QueryRun:
    """One uniform proof guess; success prob 1/R; a miss destroys the swarm."""

    hit = rng.randrange(residual_size) == 0 if residual_size > 0 else True
    return QueryRun("blind_one_shot", False, (1 if hit else None), hit, destroyed=not hit)


def candidate_elimination(residual_size: int, true_index: int, *, one_shot: bool) -> QueryRun:
    """Guess candidates in order. Retries: recover in true_index+1. One-shot: one guess only."""

    if one_shot:
        hit = true_index == 0
        return QueryRun("candidate_elimination", False, (1 if hit else None), hit, destroyed=not hit)
    return QueryRun("candidate_elimination", True, true_index + 1, True, destroyed=False)


def binary_search_oracle(residual_size: int) -> QueryRun:
    """Non-destructive fit/no-fit oracle halves the set; recover in ~log2(R) + 1 (one-shot-proof)."""

    q = max(1, math.ceil(math.log2(residual_size))) if residual_size > 1 else 0
    return QueryRun("binary_search_oracle", False, q + 1, True, destroyed=False)


def measure_one_shot_recovery(residual_size: int, *, trials: int, seed: int = 0) -> dict:
    """Empirical one-shot recovery rate over `trials` (a binomial with p = 1/R) + CI."""

    rng = random.Random(seed)
    hits = sum(1 for _ in range(trials) if blind_one_shot(residual_size, rng).recovered)
    low, high = clopper_pearson(hits, trials)
    return {
        "residual_size": residual_size,
        "trials": trials,
        "recoveries": hits,
        "recovery_rate": hits / trials if trials else 0.0,
        "recovery_rate_ci95": {"low": low, "high": high},
        "analytic_recovery_prob": 1.0 / residual_size if residual_size else 1.0,
    }
