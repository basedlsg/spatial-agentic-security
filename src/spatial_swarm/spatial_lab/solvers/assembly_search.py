"""Lab B solver: find a valid piece by connected-subset constraint search.

Enumerates connected k-voxel subsets of the available region (the target shape
minus any revealed neighbor pieces) via the ESU connected-subgraph enumeration,
prunes by published connector/topology constraints, and commit-tests survivors.
"""

from __future__ import annotations

from itertools import combinations
from typing import Iterator, Optional

from spatial_swarm.spatial_lab import commit as C
from spatial_swarm.spatial_lab import shapes as S
from spatial_swarm.spatial_lab.solvers.base import Budget, SolverResult

Coord = tuple[int, int, int]


def connected_subsets(region, k: int) -> Iterator[frozenset[Coord]]:
    """Yield every connected (6-adjacency) size-k subset of `region` exactly once (ESU)."""

    region = frozenset(region)
    ordered = sorted(region)
    index = {c: i for i, c in enumerate(ordered)}
    nbrs = {c: [n for n in S.neighbors6(c) if n in region] for c in ordered}

    def extend(sub: set, ext: set, root_idx: int) -> Iterator[frozenset[Coord]]:
        if len(sub) == k:
            yield frozenset(sub)
            return
        sub_neighbors = set().union(*(nbrs[c] for c in sub)) if sub else set()
        ext = set(ext)
        while ext:
            w = ext.pop()
            excl = {
                u
                for u in nbrs[w]
                if u not in sub and u not in sub_neighbors and index[u] > root_idx
            }
            yield from extend(sub | {w}, ext | excl, root_idx)

    for i, v in enumerate(ordered):
        start_ext = {u for u in nbrs[v] if index[u] > i}
        yield from extend({v}, start_ext, i)


def solve_backtrack(
    *,
    target,
    region,
    k: int,
    commitment: str,
    swarm_id: str,
    agent_id: str,
    repr_name: str,
    required_connector: Optional[str],
    required_topology: Optional[tuple],
    budget: Budget,
    exact: bool,
    require_connected: bool = True,
) -> SolverResult:
    budget.reset()
    target = frozenset(target)
    region = frozenset(region)
    guesses = 0
    nodes = 0
    consistent = 0
    found_piece = None
    budget_hit = False
    exhausted = True

    if require_connected:
        candidate_iter: Iterator[frozenset[Coord]] = connected_subsets(region, k)
    else:
        candidate_iter = (frozenset(c) for c in combinations(sorted(region), k))

    for candidate in candidate_iter:
        nodes += 1
        if budget.tripped(nodes):
            budget_hit = True
            exhausted = False
            break
        # constraint pruning
        if required_connector is not None and S.connector_signature(candidate, target) != required_connector:
            continue
        if required_topology is not None and S.topology_signature(candidate) != tuple(required_topology):
            continue
        consistent += 1
        guesses += 1
        if C.opens(commitment, swarm_id, agent_id, repr_name, candidate):
            found_piece = candidate
            if not exact:
                exhausted = False  # stopped early on success
                break

    return SolverResult(
        found=found_piece is not None,
        nodes_expanded=nodes,
        guesses=guesses,
        wall_seconds=budget.elapsed(),
        budget_hit=budget_hit,
        exhausted=exhausted and not budget_hit,
        recovered=found_piece,
        consistent_candidates=consistent if (exhausted and not budget_hit) else None,
        method="assembly_backtrack",
    )
