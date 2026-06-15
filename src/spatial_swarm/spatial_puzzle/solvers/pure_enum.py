"""Ground-truth solver: enumerate connected k-subsets (ESU) and check clues+commitment.

Pure Python, no external dependency, so the core residual measurement is always
reproducible. Reuses the ESU connected-subset enumerator from spatial_lab; this is
also the efficient baseline the external solvers are bake-offed against.
"""

from __future__ import annotations

from itertools import combinations

from spatial_swarm.spatial_lab.solvers.assembly_search import connected_subsets
from spatial_swarm.spatial_lab.solvers.base import Budget, SolverResult
from spatial_swarm.spatial_puzzle.solvers.consume import CluePredicate, consume


def solve(
    *,
    region,
    k: int,
    commitment: str,
    swarm_id: str,
    agent_id: str,
    repr_name: str,
    clue_predicate: CluePredicate = lambda _s: True,
    budget: Budget,
    mode: str = "count",
    require_connected: bool = True,
) -> SolverResult:
    region = frozenset(region)
    if require_connected:
        candidates = connected_subsets(region, k)
    else:
        candidates = (frozenset(c) for c in combinations(sorted(region), k))
    return consume(
        candidates,
        commitment=commitment,
        swarm_id=swarm_id,
        agent_id=agent_id,
        repr_name=repr_name,
        clue_predicate=clue_predicate,
        budget=budget,
        mode=mode,
        method="pure_enum",
        exhaustive_source=True,
    )
