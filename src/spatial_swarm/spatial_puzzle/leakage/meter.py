"""Leakage meter: exact residual candidate count per observation level vs the random ceiling.

For each accepted/built puzzle and level, count the candidates consistent with the
published lossy clues (pure_enum, exact). The random secret at matched entropy has
residual equal to the O1 outer-shape count (no structure to prune), so that level is
the ceiling. one_shot_success_prob = 1/residual. Structure can only reduce residual,
so every spatial cell is reported with its delta below the ceiling.
"""

from __future__ import annotations

import math
import random
import statistics
from typing import Optional

from spatial_swarm.experiments.metrics import _latency_summary
from spatial_swarm.spatial_lab.solvers.base import Budget
from spatial_swarm.spatial_puzzle.generators.build import build_hidden_solution, derive_public_view
from spatial_swarm.spatial_puzzle.generators.visibility import clue_predicate_for, region_for
from spatial_swarm.spatial_puzzle.leakage.ladder import RANDOM_CEILING_LABEL, enumerable_levels
from spatial_swarm.spatial_puzzle.solvers import pure_enum


def _residual(sol, agent, flags, budget) -> Optional[int]:
    view = derive_public_view(sol, agent, **flags)
    region = region_for(view)
    if not region:
        return None
    res = pure_enum.solve(
        region=region, k=sol.k, commitment=view.commitment, swarm_id=sol.swarm_id,
        agent_id=agent, repr_name=sol.repr_name, clue_predicate=clue_predicate_for(view),
        budget=budget, mode="count", require_connected=True,
    )
    return res.consistent_candidates if (res.exhausted and not res.budget_hit) else None


def measure_ladder(
    *,
    n: int = 3,
    k: int = 4,
    seeds: int = 20,
    alphabet_size: int = 4,
    topo_bucket: int = 2,
    budget: tuple[float, int] = (5.0, 3_000_000),
    seed_base: int = 1000,
) -> dict:
    levels = enumerable_levels(n)
    per_level: dict[str, list[int]] = {label: [] for label, _ in levels}
    ceilings: list[int] = []

    for s in range(seed_base, seed_base + seeds):
        sol = build_hidden_solution(
            random.Random(s), n=n, k=k, swarm_id=f"leak-{s}", alphabet_size=alphabet_size,
            topo_bucket=topo_bucket,
        )
        agent = sol.agent_ids()[len(sol.agent_ids()) // 2]
        residuals = {}
        for label, flags in levels:
            r = _residual(sol, agent, flags, Budget(*budget))
            if r is not None:
                per_level[label].append(r)
                residuals[label] = r
        if RANDOM_CEILING_LABEL in residuals:
            ceilings.append(residuals[RANDOM_CEILING_LABEL])

    ceiling_med = statistics.median(ceilings) if ceilings else None
    cells = {}
    for label, _ in levels:
        vals = per_level[label]
        if not vals:
            cells[label] = {"residual": None, "note": "not enumerable within budget"}
            continue
        med = statistics.median(vals)
        cells[label] = {
            "trials": len(vals),
            "residual_median": med,
            "residual": _latency_summary([float(v) for v in vals]),
            "one_shot_success_prob_median": 1.0 / med if med else 1.0,
            "entropy_bits_median": math.log2(med) if med else 0.0,
            "delta_below_random_ceiling_bits": (
                math.log2(ceiling_med) - math.log2(med) if (ceiling_med and med) else None
            ),
        }
    return {
        "config": {"n": n, "k": k, "seeds": seeds, "alphabet_size": alphabet_size, "topo_bucket": topo_bucket},
        "random_ceiling": {
            "label": RANDOM_CEILING_LABEL,
            "residual_median": ceiling_med,
            "one_shot_success_prob_median": 1.0 / ceiling_med if ceiling_med else 1.0,
            "note": "random secret at matched entropy: residual unchanged by clues",
        },
        "levels": cells,
    }
