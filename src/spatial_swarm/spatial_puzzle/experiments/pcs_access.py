"""Attacker access levels A0..A8 and the second-factor residual under each.

For the SPATIAL arm the residual is the number of connected k-subsets of the target's
outer shape MINUS any stolen neighbor cells (the hidden connectors/topology are never
published, so the attacker cannot prune with them -- they only help the generator reject
weak puzzles). For the RANDOM arms the second factor is independent of other agents, so
stolen neighbors reveal nothing and the residual is the full matched space (reported
analytically as one_shot_success = 2^-bits, residual too large to enumerate).

A8 (LLM/vision) is recorded as not_run unless a model endpoint exists.
"""

from __future__ import annotations

from dataclasses import dataclass

from spatial_swarm.spatial_lab.solvers.base import Budget
from spatial_swarm.spatial_puzzle.experiments.pcs_systems import Arm
from spatial_swarm.spatial_puzzle.generators.build import derive_public_view
from spatial_swarm.spatial_puzzle.generators.visibility import clue_predicate_for, region_for
from spatial_swarm.spatial_puzzle.solvers import pure_enum


@dataclass(frozen=True)
class AccessLevel:
    name: str
    revealed_neighbors: int   # how many neighbor second-factor pieces the attacker holds
    runs: bool                # False => recorded as not_run (e.g. A8 with no endpoint)
    description: str


ACCESS_LEVELS = (
    AccessLevel("A0_public_only", 0, True, "public commitments + swarm metadata; no pieces"),
    AccessLevel("A1_old_transcripts", 0, True, "old transcripts + proof metadata; no raw pieces"),
    AccessLevel("A2_one_stolen_neighbor", 1, True, "one neighboring second-factor piece"),
    AccessLevel("A3_two_stolen_neighbors", 2, True, "two neighboring second-factor pieces"),
    AccessLevel("A4_one_stolen_sidecar_non_target", 1, True, "one full non-target sidecar"),
    AccessLevel("A5_partial_gateway_snapshot", 0, True, "verifier-visible state only; no secret/key"),
    AccessLevel("A6_artifact_directory", 0, True, "run logs + metrics + redacted artifacts"),
    AccessLevel("A7_solver_generated_near_miss", 0, True, "attacker runs solvers to craft wrong pieces"),
    AccessLevel("A8_llm_or_vision_candidate", 0, False, "model-generated candidate (not_run if no endpoint)"),
)


def _spatial_residual(arm: Arm, revealed_count: int, budget: tuple[float, int]) -> dict:
    rc = min(revealed_count, max(0, len(arm.neighbors)))
    view = derive_public_view(
        arm.sol, arm.target_agent, shape=True, revealed_count=rc, connector=False, topology=False
    )
    region = region_for(view)
    if not region:
        return {"residual_count": None, "one_shot_success_prob": None, "enumerated": False,
                "budget_hit": False, "nodes": 0, "wall_seconds": 0.0, "best_estimate": None}
    res = pure_enum.solve(
        region=region, k=arm.k, commitment=view.commitment, swarm_id=arm.sol.swarm_id,
        agent_id=arm.target_agent, repr_name=arm.repr_name, clue_predicate=clue_predicate_for(view),
        budget=Budget(*budget), mode="count", require_connected=True,
    )
    if res.exhausted and not res.budget_hit and res.consistent_candidates:
        count = res.consistent_candidates
        return {"residual_count": count, "one_shot_success_prob": 1.0 / count, "enumerated": True,
                "budget_hit": False, "nodes": res.nodes_expanded, "wall_seconds": res.wall_seconds,
                "best_estimate": count}
    # not enumerable within budget: report "not solved within budget", never "hard"
    return {"residual_count": None, "one_shot_success_prob": None, "enumerated": False,
            "budget_hit": res.budget_hit, "nodes": res.nodes_expanded, "wall_seconds": res.wall_seconds,
            "best_estimate": None}


def second_factor_residual(arm: Arm, level: AccessLevel, budget: tuple[float, int]) -> dict:
    """Residual / one-shot success of the second factor for one arm at one access level."""

    if not level.runs:
        return {"status": "not_run", "reason": "no_model_endpoint"}
    if arm.kind == "spatial":
        out = _spatial_residual(arm, level.revealed_neighbors, budget)
        out["status"] = "ok"
        return out
    # random arms: second factor independent of other agents -> residual is the full space
    return {
        "status": "ok",
        "residual_count": None,                                   # too large to enumerate
        "one_shot_success_prob": 2.0 ** (-arm.second_factor_bits),
        "enumerated": False,
        "budget_hit": False,
        "nodes": 0,
        "wall_seconds": 0.0,
        "best_estimate": None,
        "note": "independent random factor: stolen neighbors reveal nothing",
    }


def residual_table(arms: dict, budget: tuple[float, int]) -> dict:
    """For each access level, the second-factor residual per arm (spatial enumeration cached)."""

    spatial_cache: dict[int, dict] = {}
    table: dict = {}
    for level in ACCESS_LEVELS:
        per_arm: dict = {}
        for kind in ("random_only", "random_plus", "spatial"):
            arm = arms[kind]
            if kind == "spatial" and level.runs:
                rc = min(level.revealed_neighbors, max(0, len(arm.neighbors)))
                if rc not in spatial_cache:
                    spatial_cache[rc] = second_factor_residual(arm, level, budget)
                per_arm[kind] = dict(spatial_cache[rc])
            else:
                per_arm[kind] = second_factor_residual(arm, level, budget)
        table[level.name] = {"revealed_neighbors": level.revealed_neighbors,
                             "description": level.description, "arms": per_arm}
    return table
