"""Rigid-pose machinery and observation generation (Lab A)."""

from __future__ import annotations

import random

from spatial_swarm.spatial_lab import observe as O
from spatial_swarm.spatial_lab import pose as P
from spatial_swarm.spatial_lab import rotations as R
from spatial_swarm.spatial_lab import shapes as S

PIECE = frozenset({(0, 0, 0), (1, 0, 0), (1, 1, 0), (1, 1, 1)})


def test_inverse_pose_recovers_original():
    rng = random.Random(0)
    for _ in range(200):
        g = P.random_pose(rng, 3)
        moved = P.apply_pose(g, PIECE)
        back = P.apply_pose(P.inverse_pose(g), moved)
        assert back == PIECE


def test_pose_space_size_formula():
    assert P.pose_space_size(0) == 24
    assert P.pose_space_size(1) == 24 * 27
    assert len(P.translation_grid(2)) == 5 ** 3


def test_observations_preserve_shape_but_hide_pose():
    rng = random.Random(1)
    obs = O.observe(PIECE, rng, 5, bound=4)
    assert len(obs) == 5
    base_orbit = R.canonical_orbit(PIECE)
    for view in obs:
        assert len(view) == len(PIECE)
        assert S.is_connected(view)
        assert R.canonical_orbit(view) == base_orbit   # same shape under rigid motion
    # observe() returns only coordinate sets, not poses
    assert all(isinstance(v, frozenset) for v in obs)


def test_observe_with_poses_consistent():
    rng = random.Random(2)
    for g, view in O.observe_with_poses(PIECE, rng, 10, bound=3):
        assert P.apply_pose(g, PIECE) == view
