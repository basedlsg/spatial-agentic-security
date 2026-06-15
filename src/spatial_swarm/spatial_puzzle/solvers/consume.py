"""Shared candidate-consumption loop used by every solver.

Each solver only differs in HOW it enumerates candidate k-subsets; they all apply
the same clue + commitment filter here, so a residual-count agreement across
solvers is by construction, not coincidence. The SHA-256 commitment is the floor:
no solver can shortcut it; it is checked per candidate. A count is trustworthy
only when the candidate source was exhaustive and the budget did not trip.
"""

from __future__ import annotations

from typing import Callable, Iterable, Optional

from spatial_swarm.spatial_lab import commit as C
from spatial_swarm.spatial_lab.solvers.base import Budget, SolverResult

CluePredicate = Callable[[frozenset], bool]


def consume(
    candidates: Iterable[frozenset],
    *,
    commitment: str,
    swarm_id: str,
    agent_id: str,
    repr_name: str,
    clue_predicate: CluePredicate,
    budget: Budget,
    mode: str,
    method: str,
    exhaustive_source: bool,
) -> SolverResult:
    budget.reset()
    nodes = 0
    guesses = 0
    consistent = 0
    found: Optional[frozenset] = None
    budget_hit = False
    completed = True
    for cand in candidates:
        nodes += 1
        if budget.tripped(nodes):
            budget_hit = True
            completed = False
            break
        if not clue_predicate(cand):
            continue
        consistent += 1
        guesses += 1
        if C.opens(commitment, swarm_id, agent_id, repr_name, cand):
            found = cand
            if mode == "recover":
                completed = False
                break
    exhausted = exhaustive_source and completed and not budget_hit
    return SolverResult(
        found=found is not None,
        nodes_expanded=nodes,
        guesses=guesses,
        wall_seconds=budget.elapsed(),
        budget_hit=budget_hit,
        exhausted=exhausted,
        recovered=found,
        consistent_candidates=consistent if exhausted else None,
        method=method,
    )
