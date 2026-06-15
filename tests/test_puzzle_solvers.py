"""Solver bake-off: independent paradigms agree on the residual; commitment is the floor."""

from __future__ import annotations

import pytest

from spatial_swarm.spatial_lab import commit as C
from spatial_swarm.spatial_lab.solvers.base import Budget
from spatial_swarm.spatial_puzzle.solvers import (
    cheap_attacks,
    cp_sat,
    graph_iso,
    pure_enum,
    sat_solver,
    smt_solver,
)
from spatial_swarm.spatial_puzzle.solvers import optional

# A small connected region (3x2x2 box = 12 cells) and a committed connected 4-piece.
REGION = frozenset({(x, y, z) for x in range(3) for y in range(2) for z in range(2)})
TRUE_PIECE = frozenset({(0, 0, 0), (1, 0, 0), (2, 0, 0), (2, 1, 0)})
SWARM, AGENT, REPR = "s", "agent_001", "P"
COMMIT = C.commit(SWARM, AGENT, REPR, TRUE_PIECE)


def _budget():
    return Budget(20.0, 5_000_000)


def _count(solve_fn):
    return solve_fn(
        region=REGION, k=4, commitment=COMMIT, swarm_id=SWARM, agent_id=AGENT,
        repr_name=REPR, budget=_budget(), mode="count", require_connected=True,
    )


def test_pure_enum_ground_truth():
    res = _count(pure_enum.solve)
    assert res.exhausted and not res.budget_hit
    assert res.consistent_candidates is not None and res.consistent_candidates >= 1
    assert res.found  # the committed piece is among the connected 4-subsets


@pytest.mark.parametrize("name,mod", [("cp_sat", cp_sat), ("sat", sat_solver), ("smt", smt_solver)])
def test_external_solvers_agree_with_pure_enum(name, mod):
    if not optional.available(name):
        pytest.skip(f"{name} unavailable: {optional.import_error(name)}")
    ground = _count(pure_enum.solve)
    res = _count(mod.solve)
    assert res.exhausted and not res.budget_hit
    assert res.consistent_candidates == ground.consistent_candidates
    assert res.found  # recovers within the residual


@pytest.mark.parametrize("name,mod", [("cp_sat", cp_sat), ("sat", sat_solver), ("smt", smt_solver)])
def test_recover_mode_finds_committed_piece(name, mod):
    if not optional.available(name):
        pytest.skip(f"{name} unavailable")
    res = mod.solve(
        region=REGION, k=4, commitment=COMMIT, swarm_id=SWARM, agent_id=AGENT,
        repr_name=REPR, budget=_budget(), mode="recover", require_connected=True,
    )
    assert res.found
    assert C.opens(COMMIT, SWARM, AGENT, REPR, res.recovered)


def test_budget_trip_never_reports_found():
    # cap nodes at 1: consume trips before checking -> no silent found, count not trusted
    res = pure_enum.solve(
        region=REGION, k=4, commitment=COMMIT, swarm_id=SWARM, agent_id=AGENT,
        repr_name=REPR, budget=Budget(60.0, 1), mode="count", require_connected=True,
    )
    assert res.budget_hit and not res.found and res.consistent_candidates is None


def test_clue_predicate_shrinks_residual():
    no_clue = _count(pure_enum.solve).consistent_candidates
    # a clue that only accepts pieces containing the origin reduces the candidate set
    with_clue = pure_enum.solve(
        region=REGION, k=4, commitment=COMMIT, swarm_id=SWARM, agent_id=AGENT, repr_name=REPR,
        clue_predicate=lambda c: (0, 0, 0) in c, budget=_budget(), mode="count", require_connected=True,
    ).consistent_candidates
    assert with_clue <= no_clue


def test_graph_iso_congruence_and_classes():
    if not optional.available("graph_iso"):
        pytest.skip("networkx unavailable")
    straight = frozenset({(0, 0, 0), (1, 0, 0), (2, 0, 0), (3, 0, 0)})
    straight_moved = frozenset({(5, 5, 5), (6, 5, 5), (7, 5, 5), (8, 5, 5)})
    bent = frozenset({(0, 0, 0), (1, 0, 0), (1, 1, 0), (1, 1, 1)})  # an L chain
    tee = frozenset({(0, 0, 0), (1, 0, 0), (2, 0, 0), (1, 1, 0)})    # degree-3 node
    assert graph_iso.pieces_isomorphic(straight, straight_moved)
    # graph-iso is the ADJACENCY-graph invariant, NOT 3D congruence: a straight and an
    # L-bent chain are both paths (P4), so they are graph-isomorphic.
    assert graph_iso.pieces_isomorphic(straight, bent)
    # a T (degree-3 node) is a different graph
    assert not graph_iso.pieces_isomorphic(straight, tee)
    # classes: {straight, straight_moved, bent} are all paths; tee is its own class
    assert graph_iso.count_shape_classes([straight, straight_moved, bent, tee]) == 2


def test_neighbor_copy_attacker():
    others = [frozenset({(0, 1, 0), (1, 1, 0)}), TRUE_PIECE]  # one of them is the real piece
    hit = cheap_attacks.neighbor_copy(
        commitment=COMMIT, swarm_id=SWARM, agent_id=AGENT, repr_name=REPR, other_pieces=others,
    )
    assert hit.found  # the planted match opens
    miss = cheap_attacks.neighbor_copy(
        commitment=COMMIT, swarm_id=SWARM, agent_id=AGENT, repr_name=REPR,
        other_pieces=[frozenset({(0, 1, 0), (1, 1, 0)})],
    )
    assert not miss.found
