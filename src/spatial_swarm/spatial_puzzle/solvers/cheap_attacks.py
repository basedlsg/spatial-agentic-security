"""Cheap attackers: neighbor-copy and transcript-leak."""

from __future__ import annotations

from spatial_swarm.spatial_lab import commit as C
from spatial_swarm.spatial_lab.solvers.base import Budget, SolverResult
from spatial_swarm.spatial_lab.solvers.registration import solve_exhaustive


def neighbor_copy(*, commitment, swarm_id, agent_id, repr_name, other_pieces) -> SolverResult:
    """Submit each stolen neighbor piece against the target commitment."""

    others = list(other_pieces)
    for p in others:
        if C.opens(commitment, swarm_id, agent_id, repr_name, frozenset(p)):
            return SolverResult(
                True, len(others), len(others), 0.0, False, True,
                recovered=frozenset(p), method="neighbor_copy",
            )
    return SolverResult(False, len(others), len(others), 0.0, False, True, method="neighbor_copy")


def transcript_leak(
    *, observations, commitment, swarm_id, agent_id, repr_name, bound, budget: Budget
) -> SolverResult:
    """Reuse a stale observation transcript via registration pose search."""

    res = solve_exhaustive(
        observations=observations, commitment=commitment, swarm_id=swarm_id,
        agent_id=agent_id, repr_name=repr_name, bound=bound, budget=budget,
    )
    res.method = "transcript_leak"
    return res
