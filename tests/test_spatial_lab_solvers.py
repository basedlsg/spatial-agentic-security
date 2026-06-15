"""Solvers and positive controls (Lab A registration, Lab B assembly)."""

from __future__ import annotations

import random

import pytest

from spatial_swarm.spatial_lab import commit as C
from spatial_swarm.spatial_lab import controls
from spatial_swarm.spatial_lab import pose as P
from spatial_swarm.spatial_lab import representations as Rep
from spatial_swarm.spatial_lab.solvers import assembly_search as A
from spatial_swarm.spatial_lab.solvers import registration as G
from spatial_swarm.spatial_lab.solvers.base import Budget

PARAMS = {"R1": {"p": 13}, "R2": {"mode": "grown"}, "R3": {"mode": "grown"}, "R4": {"mode": "grown"}}


# ---- connected-subset enumerator (ESU) ----

def test_connected_subset_counts():
    square = frozenset({(0, 0, 0), (1, 0, 0), (0, 1, 0), (1, 1, 0)})
    assert len(list(A.connected_subsets(square, 1))) == 4
    assert len(list(A.connected_subsets(square, 2))) == 4   # the 4 edges
    assert len(list(A.connected_subsets(square, 3))) == 4   # the 4 L-trominoes
    assert len(list(A.connected_subsets(square, 4))) == 1   # the whole square
    # no duplicates
    subs = list(A.connected_subsets(square, 3))
    assert len(subs) == len(set(subs))


# ---- registration solver (Lab A) ----

@pytest.mark.parametrize("repr_name", ["R1", "R2", "R3", "R4"])
def test_registration_recovers_a_random_pose(repr_name):
    rng = random.Random(4)
    sw = Rep.build_swarm(repr_name, rng, 3, 4, PARAMS[repr_name], "s")
    agent = sw.agent_ids()[1]
    piece = sw.pieces[agent]
    bound = 2
    observations = P_observe(piece, random.Random(9), bound)
    res = G.solve_exhaustive(
        observations=observations, commitment=sw.commitments[agent], swarm_id=sw.swarm_id,
        agent_id=agent, repr_name=repr_name, bound=bound, budget=Budget(5.0, 5_000_000),
    )
    assert res.found
    assert C.opens(sw.commitments[agent], sw.swarm_id, agent, repr_name, res.recovered)
    assert res.pose_space_size == P.pose_space_size(bound)


def P_observe(piece, rng, bound):
    return [P.apply_pose(P.random_pose(rng, bound), piece)]


def test_local_window_misses_when_translation_exceeds_window():
    rng = random.Random(1)
    sw = Rep.build_swarm("R2", rng, 3, 4, {"mode": "grown"}, "s")
    agent = sw.agent_ids()[1]
    piece = sw.pieces[agent]
    # force a large translation outside the heuristic window
    far = P.RigidPose(rot_index=0, translation=(6, 6, 6))
    obs = [P.apply_pose(far, piece)]
    res = G.solve_local_window(
        observations=obs, commitment=sw.commitments[agent], swarm_id=sw.swarm_id,
        agent_id=agent, repr_name="R2", window=1, budget=Budget(5.0, 5_000_000),
    )
    assert not res.found and not res.budget_hit and res.exhausted   # honest miss, not a budget stop


def test_budget_trip_never_reports_found():
    rng = random.Random(2)
    sw = Rep.build_swarm("R2", rng, 3, 4, {"mode": "grown"}, "s")
    agent = sw.agent_ids()[1]
    obs = [P.apply_pose(P.random_pose(random.Random(5), 3), sw.pieces[agent])]
    res = G.solve_exhaustive(
        observations=obs, commitment=sw.commitments[agent], swarm_id=sw.swarm_id,
        agent_id=agent, repr_name="R2", bound=3, budget=Budget(max_seconds=10.0, max_nodes=1),
    )
    assert res.budget_hit and not res.found


# ---- assembly solver (Lab B) ----

def test_assembly_exact_candidate_count_and_find():
    rng = random.Random(3)
    sw = Rep.build_swarm("R2", rng, 3, 4, {"mode": "grown"}, "s")
    agent = sw.agent_ids()[1]
    res = A.solve_backtrack(
        target=sw.target, region=sw.target, k=4, commitment=sw.commitments[agent],
        swarm_id=sw.swarm_id, agent_id=agent, repr_name="R2",
        required_connector=None, required_topology=None,
        budget=Budget(10.0, 5_000_000), exact=True, require_connected=True,
    )
    assert res.found
    assert res.exhausted and not res.budget_hit
    assert res.consistent_candidates is not None and res.consistent_candidates >= 1


# ---- positive controls (gate the experiment) ----

@pytest.mark.parametrize("repr_name", controls.LAB_A_REPRS)
def test_planted_pose_control_passes(repr_name):
    ok = controls.check_planted_pose(
        repr_name, random.Random(7), 3, 4, PARAMS[repr_name], "s", bound=2,
        budget=Budget(5.0, 5_000_000),
    )
    assert ok


@pytest.mark.parametrize("repr_name", controls.LAB_B_REPRS)
def test_planted_piece_control_passes(repr_name):
    ok = controls.check_planted_piece(
        repr_name, random.Random(7), 3, 4, PARAMS[repr_name], "s",
        budget=Budget(10.0, 5_000_000),
    )
    assert ok
