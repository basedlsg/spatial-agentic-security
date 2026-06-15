"""The five spatial-puzzle experiments, each with the random baseline / ceiling.

adversarial_generation : generator yield + reason histogram + accepted residuals
leakage_ladder         : residual per observation level vs the random ceiling
one_shot_vs_retry      : one-shot recovery prob for spatial residual vs random ceiling
partial_compromise     : residual as neighbor pieces are stolen (O1/O3/O4)
solver_bakeoff         : pure/CP-SAT/SAT/SMT agree on the residual; commitment is the floor
"""

from __future__ import annotations

import random
import statistics
from collections import Counter

from spatial_swarm.spatial_lab.solvers.base import Budget
from spatial_swarm.spatial_puzzle.enclave.query_attacker import measure_one_shot_recovery
from spatial_swarm.spatial_puzzle.generators.build import build_hidden_solution, derive_public_view
from spatial_swarm.spatial_puzzle.generators.rejection import evaluate_candidate, generate_accepted
from spatial_swarm.spatial_puzzle.generators.visibility import clue_predicate_for, region_for
from spatial_swarm.spatial_puzzle.leakage.meter import measure_ladder
from spatial_swarm.spatial_puzzle.solvers import cp_sat, optional, pure_enum, sat_solver, smt_solver


def run_adversarial_generation(*, n, k, seeds, ambiguity_target=4, alphabet_size=4, seed_base=1000) -> dict:
    accepted = 0
    residuals = []
    reasons: Counter = Counter()
    total_attempts = 0
    for s in range(seed_base, seed_base + seeds):
        _sol, stats = generate_accepted(
            random.Random(s), n=n, k=k, swarm_id=f"adv-{s}", ambiguity_target=ambiguity_target,
            alphabet_size=alphabet_size, max_generation_attempts=80,
        )
        total_attempts += stats["attempts"]
        if stats["accepted"]:
            accepted += 1
            if stats["accepted_residual"]:
                residuals.append(stats["accepted_residual"])
        for r, c in stats["reason_histogram"].items():
            reasons[r] += c
    return {
        "trials": seeds, "accepted": accepted, "acceptance_rate": accepted / seeds if seeds else 0.0,
        "total_attempts": total_attempts,
        "median_accepted_residual": statistics.median(residuals) if residuals else None,
        "reason_histogram": dict(reasons),
    }


def run_leakage_ladder(*, n, k, seeds, alphabet_size=4, seed_base=2000) -> dict:
    return measure_ladder(n=n, k=k, seeds=seeds, alphabet_size=alphabet_size, seed_base=seed_base)


def run_one_shot_vs_retry(*, n, k, seeds, alphabet_size=4, seed_base=3000, trials=4000) -> dict:
    ladder = measure_ladder(n=n, k=k, seeds=seeds, alphabet_size=alphabet_size, seed_base=seed_base)
    ceiling = ladder["random_ceiling"]["residual_median"]
    post = ladder["levels"].get("O7O8_both_hints", {}).get("residual_median")
    out = {"note": "one-shot recovery prob ~ 1/residual; larger residual (random ceiling) is safer"}
    if ceiling:
        out["random_ceiling"] = measure_one_shot_recovery(int(round(ceiling)), trials=trials, seed=1)
    if post:
        out["spatial_post_clue"] = measure_one_shot_recovery(int(round(post)), trials=trials, seed=1)
    return out


def run_partial_compromise(*, n, k, seeds, alphabet_size=4, seed_base=4000) -> dict:
    ladder = measure_ladder(n=n, k=k, seeds=seeds, alphabet_size=alphabet_size, seed_base=seed_base)
    lv = ladder["levels"]
    return {
        "residual_vs_stolen_neighbors": {
            "0_revealed": lv.get("O1_outer_shape", {}).get("residual_median"),
            "1_revealed": lv.get("O3_one_neighbor", {}).get("residual_median"),
            "1_revealed_plus_hints": lv.get("O10_stolen_sidecar", {}).get("residual_median"),
            "all_revealed": lv.get("O4_all_neighbors", {}).get("residual_median"),
        },
        "note": "stealing sidecars shrinks residual monotonically; all-but-one -> the complement (1)",
    }


def run_solver_bakeoff(*, n, k, seed=7, budget=(20.0, 5_000_000)) -> dict:
    sol = build_hidden_solution(random.Random(seed), n=n, k=k, swarm_id="bake")
    agent = sol.agent_ids()[len(sol.agent_ids()) // 2]
    view = derive_public_view(sol, agent, shape=True, revealed_count=0, connector=False, topology=False)
    region, pred = region_for(view), clue_predicate_for(view)
    results: dict = {}
    for name, fn in (("pure_enum", pure_enum.solve), ("cp_sat", cp_sat.solve), ("sat", sat_solver.solve), ("smt", smt_solver.solve)):
        if name != "pure_enum" and not optional.available(name):
            results[name] = {"status": "solver_unavailable", "error": optional.import_error(name)}
            continue
        r = fn(
            region=region, k=sol.k, commitment=sol.commitments[agent], swarm_id=sol.swarm_id,
            agent_id=agent, repr_name=sol.repr_name, clue_predicate=pred, budget=Budget(*budget),
            mode="count", require_connected=True,
        )
        results[name] = {
            "consistent_candidates": r.consistent_candidates, "nodes": r.nodes_expanded,
            "wall_seconds": r.wall_seconds, "exhausted": r.exhausted, "budget_hit": r.budget_hit,
            "found": r.found,
        }
    counts = {nm: v["consistent_candidates"] for nm, v in results.items()
              if isinstance(v, dict) and v.get("consistent_candidates") is not None}
    return {
        "results": results,
        "all_agree_on_residual": len(set(counts.values())) <= 1,
        "residual": next(iter(counts.values())) if counts else None,
    }


def positive_controls(*, n, k, seeds=5, seed_base=9000) -> dict:
    passes = 0
    for s in range(seed_base, seed_base + seeds):
        sol = build_hidden_solution(random.Random(s), n=n, k=k, swarm_id=f"ctrl-{s}")
        v = evaluate_candidate(sol, ambiguity_target=1, budget_factory=lambda: Budget(10.0, 2_000_000))
        passes += int(v.controls_pass)
    return {"trials": seeds, "passes": passes, "valid": passes == seeds}


def run_all(*, n=3, k=4, seeds=12) -> dict:
    return {
        "config": {"n": n, "k": k, "seeds": seeds},
        "positive_controls": positive_controls(n=n, k=k),
        "adversarial_generation": run_adversarial_generation(n=n, k=k, seeds=seeds),
        "leakage_ladder": run_leakage_ladder(n=n, k=k, seeds=seeds),
        "one_shot_vs_retry": run_one_shot_vs_retry(n=n, k=k, seeds=seeds),
        "partial_compromise": run_partial_compromise(n=n, k=k, seeds=seeds),
        "solver_bakeoff": run_solver_bakeoff(n=n, k=k),
    }
