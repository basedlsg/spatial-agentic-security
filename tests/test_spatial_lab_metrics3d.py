"""Reconstruction-error metrics."""

from __future__ import annotations

import random

from spatial_swarm.spatial_lab import metrics3d as M
from spatial_swarm.spatial_lab import rotations as R
from spatial_swarm.spatial_lab import shapes as S

PIECE = frozenset({(0, 0, 0), (1, 0, 0), (1, 1, 0), (1, 1, 1)})


def test_identity_scores_perfect():
    assert M.iou(PIECE, PIECE) == 1.0
    assert M.dice(PIECE, PIECE) == 1.0
    assert M.surface_match(PIECE, PIECE) == 1.0
    assert M.chamfer_distance(PIECE, PIECE) == 0.0
    assert M.hausdorff_distance(PIECE, PIECE) == 0.0


def test_pose_image_scores_perfect():
    # any rotation+translation of the piece is the same shape -> IoU 1
    for i in range(len(R.ROTATIONS)):
        posed = frozenset((x + 3, y - 1, z + 4) for x, y, z in R.apply_set(i, PIECE))
        assert M.iou(posed, PIECE) == 1.0
        assert M.chamfer_distance(posed, PIECE) == 0.0


def test_empty_and_disjoint():
    assert M.iou(frozenset(), PIECE) == 0.0
    assert M.iou(frozenset(), frozenset()) == 1.0


def test_different_shapes_below_one():
    straight = frozenset({(0, 0, 0), (1, 0, 0), (2, 0, 0), (3, 0, 0)})
    assert M.iou(straight, PIECE) < 1.0
    assert M.dice(straight, PIECE) < 1.0


def test_bounds_and_symmetry_random():
    rng = random.Random(0)
    grid = [(x, y, z) for x in range(4) for y in range(4) for z in range(4)]
    for _ in range(40):
        a = frozenset(rng.sample(grid, 4))
        b = frozenset(rng.sample(grid, 4))
        for fn in (M.iou, M.dice, M.surface_match):
            v = fn(a, b)
            assert 0.0 <= v <= 1.0
        assert abs(M.iou(a, b) - M.iou(b, a)) < 1e-9   # symmetric
        assert M.chamfer_distance(a, b) >= 0.0


def test_surface_match_uses_surface_area():
    single = frozenset({(0, 0, 0)})
    assert S.surface_area(single) == 6
    assert M.surface_match(single, single) == 1.0
