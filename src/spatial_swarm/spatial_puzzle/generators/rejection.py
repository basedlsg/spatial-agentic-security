"""Rejection loop: keep only puzzles that stay ambiguous and leak through no single clue.

Reject if: residual at the partial-observation level collapses below the ambiguity
target; any single public clue uniquely identifies the piece; a neighbor piece opens
the commitment; or the secret piece is congruent (graph-iso) to a neighbor. Accept
only if none fire AND the positive control passes (the true piece is in the residual,
so a 0-residual reject can never be a broken enumerator). The acceptance yield and
reason histogram are returned, because a near-zero yield is itself evidence that
structure collapses residual.
"""

from __future__ import annotations

import random
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

from spatial_swarm.spatial_lab.solvers.base import Budget
from spatial_swarm.spatial_puzzle.generators.build import build_hidden_solution, derive_public_view
from spatial_swarm.spatial_puzzle.generators.visibility import (
    HiddenSolution,
    clue_predicate_for,
    region_for,
)
from spatial_swarm.spatial_puzzle.solvers import cheap_attacks, graph_iso, pure_enum


@dataclass
class RejectionVerdict:
    accepted: bool
    reasons: list[str]
    residual_at_partial: Optional[int]
    per_clue_residual: dict[str, Optional[int]] = field(default_factory=dict)
    controls_pass: bool = False


def _residual(sol: HiddenSolution, agent: str, *, shape, revealed_count, connector, topology, budget: Budget):
    view = derive_public_view(
        sol, agent, shape=shape, revealed_count=revealed_count, connector=connector, topology=topology
    )
    region = region_for(view)
    if not region:
        return None, False
    res = pure_enum.solve(
        region=region, k=sol.k, commitment=view.commitment, swarm_id=sol.swarm_id,
        agent_id=agent, repr_name=sol.repr_name, clue_predicate=clue_predicate_for(view),
        budget=budget, mode="count", require_connected=True,
    )
    if res.exhausted and not res.budget_hit:
        return res.consistent_candidates, res.found
    return None, res.found


def evaluate_candidate(
    sol: HiddenSolution, *, ambiguity_target: int, budget_factory,
    min_solver_budget: Optional[tuple] = None,
) -> RejectionVerdict:
    agent = sol.agent_ids()[len(sol.agent_ids()) // 2]
    reasons: list[str] = []
    per_clue: dict[str, Optional[int]] = {}

    # partial-observation level: outer shape + both lossy clues, NO neighbors revealed.
    residual, found_true = _residual(
        sol, agent, shape=True, revealed_count=0, connector=True, topology=True, budget=budget_factory()
    )
    per_clue["shape+connector+topology"] = residual
    controls_pass = bool(found_true)  # the true piece must be in the residual
    if residual is None or residual < ambiguity_target:
        reasons.append("residual_collapse")

    # single-clue uniqueness (each clue alone must not pin the piece to 1)
    for label, kw in (
        ("shape_only", dict(shape=True, revealed_count=0, connector=False, topology=False)),
        ("connector_only", dict(shape=True, revealed_count=0, connector=True, topology=False)),
        ("topology_only", dict(shape=True, revealed_count=0, connector=False, topology=True)),
    ):
        r, _ = _residual(sol, agent, budget=budget_factory(), **kw)
        per_clue[label] = r
        if r == 1:
            reasons.append(f"unique_by_{label}")

    # neighbor-copy and congruence leaks
    others = [p for a, p in sol.pieces.items() if a != agent]
    if cheap_attacks.neighbor_copy(
        commitment=sol.commitments[agent], swarm_id=sol.swarm_id, agent_id=agent,
        repr_name=sol.repr_name, other_pieces=others,
    ).found:
        reasons.append("neighbor_copy")
    if graph_iso.congruence_leak(sol.pieces[agent], others):
        reasons.append("congruence_leak")

    # adversarial filter: reject if a fast solver opens the target below a minimum budget
    if min_solver_budget is not None:
        r = pure_enum.solve(
            region=sol.target, k=sol.k, commitment=sol.commitments[agent], swarm_id=sol.swarm_id,
            agent_id=agent, repr_name=sol.repr_name, budget=Budget(*min_solver_budget),
            mode="recover", require_connected=True,
        )
        if r.found:
            reasons.append("solver_open_fast")

    accepted = (not reasons) and controls_pass
    return RejectionVerdict(accepted, reasons, residual, per_clue, controls_pass)


def generate_accepted(
    rng: random.Random,
    *,
    n: int,
    k: int,
    swarm_id: str,
    ambiguity_target: int = 4,
    alphabet_size: int = 4,
    topo_bucket: int = 2,
    budget: tuple[float, int] = (3.0, 1_000_000),
    max_generation_attempts: int = 300,
    min_solver_budget: Optional[tuple] = None,
) -> tuple[Optional[HiddenSolution], dict]:
    """Loop until a puzzle survives the suite; return it plus yield + reason histogram.

    `min_solver_budget` enables the adversarial filter (reject if a fast solver opens the
    target below that budget) on top of the standard rejection reasons.
    """

    reasons = Counter()
    attempts = 0
    accepted_sol: Optional[HiddenSolution] = None
    accepted_verdict: Optional[RejectionVerdict] = None
    for _ in range(max_generation_attempts):
        attempts += 1
        sol = build_hidden_solution(
            rng, n=n, k=k, swarm_id=f"{swarm_id}-{attempts}", alphabet_size=alphabet_size,
            topo_bucket=topo_bucket,
        )
        verdict = evaluate_candidate(
            sol, ambiguity_target=ambiguity_target, budget_factory=lambda: Budget(*budget),
            min_solver_budget=min_solver_budget,
        )
        if verdict.accepted:
            accepted_sol, accepted_verdict = sol, verdict
            break
        for r in (verdict.reasons or ["unknown"]):
            reasons[r] += 1
    stats = {
        "attempts": attempts,
        "accepted": accepted_sol is not None,
        "acceptance_yield": (1.0 / attempts) if accepted_sol is not None else 0.0,
        "reason_histogram": dict(reasons),
        "accepted_residual": accepted_verdict.residual_at_partial if accepted_verdict else None,
    }
    return accepted_sol, stats
