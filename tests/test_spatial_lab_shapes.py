"""Voxel shape generation, partition, connectors, topology."""

from __future__ import annotations

import random

import pytest

from spatial_swarm.spatial_lab import rotations as R
from spatial_swarm.spatial_lab import shapes as S


def test_is_connected():
    assert S.is_connected({(0, 0, 0), (1, 0, 0), (2, 0, 0)})
    assert not S.is_connected({(0, 0, 0), (2, 0, 0)})
    assert not S.is_connected(set())


@pytest.mark.parametrize("mode", ["solid_box", "random_polycube"])
def test_generate_target_connected_exact_size(mode):
    rng = random.Random(1)
    target = S.generate_target(rng, 4, 6, mode)
    assert len(target) == 24
    assert S.is_connected(target)


@pytest.mark.parametrize("mode", ["solid_box", "grown"])
@pytest.mark.parametrize("seed", [1, 2, 3, 7, 11, 19, 42])
def test_partition_is_connected_exact_cover(mode, seed):
    rng = random.Random(seed)
    n, k = 4, 5
    target, pieces = S.generate_partitioned(rng, n, k, mode)
    assert len(pieces) == n
    assert S.is_connected(target)
    union = set()
    for p in pieces.values():
        assert len(p) == k
        assert S.is_connected(p)
        assert union.isdisjoint(p)
        union |= set(p)
    assert union == set(target)


def test_surface_area_known_values():
    assert S.surface_area({(0, 0, 0)}) == 6
    assert S.surface_area({(0, 0, 0), (1, 0, 0)}) == 10


def test_complement_components_detects_hole():
    solid_3x3 = {(x, y, 0) for x in range(3) for y in range(3)}
    ring = solid_3x3 - {(1, 1, 0)}
    assert S.complement_components(solid_3x3) == 0   # no empty cell in bbox
    assert S.complement_components(ring) == 1        # the enclosed center


def test_articulation_count():
    line = {(0, 0, 0), (1, 0, 0), (2, 0, 0)}
    assert S.articulation_count(line) == 1   # removing the middle splits it
    square = {(0, 0, 0), (1, 0, 0), (0, 1, 0), (1, 1, 0)}
    assert S.articulation_count(square) == 0


def test_topology_signature_is_pose_invariant():
    piece = frozenset({(0, 0, 0), (1, 0, 0), (1, 1, 0), (1, 1, 1)})
    base = S.topology_signature(piece)
    for i in range(len(R.ROTATIONS)):
        rotated = R.apply_set(i, piece)
        shifted = frozenset((x + 4, y - 2, z + 7) for x, y, z in rotated)
        assert S.topology_signature(shifted) == base


def test_connector_signature_deterministic_and_distinguishes():
    target = frozenset({(x, 0, 0) for x in range(4)})  # a 4-line, two 2-pieces
    left = frozenset({(0, 0, 0), (1, 0, 0)})
    right = frozenset({(2, 0, 0), (3, 0, 0)})
    s_left = S.connector_signature(left, target)
    assert s_left == S.connector_signature(left, target)  # deterministic
    # a piece with no internal boundary (whole target) has the empty signature
    whole = S.connector_signature(target, target)
    assert whole != s_left
    assert S.connector_signature(right, target) is not None
