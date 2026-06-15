"""Cube rotation group invariants."""

from __future__ import annotations

from spatial_swarm.spatial_lab import rotations as R


def test_group_has_24_distinct_proper_rotations():
    assert len(R.ROTATIONS) == 24
    assert len(set(R.ROTATIONS)) == 24
    for m in R.ROTATIONS:
        assert R._det3(m) == 1


def test_identity_present_and_acts_trivially():
    assert R.apply(R.IDENTITY_INDEX, (2, 3, 5)) == (2, 3, 5)


def test_closure_and_inverse_in_group():
    n = len(R.ROTATIONS)
    for i in range(n):
        assert 0 <= R.inverse(i) < n
        assert R.compose(i, R.inverse(i)) == R.IDENTITY_INDEX
        for j in range(n):
            assert 0 <= R.compose(i, j) < n  # composition stays in the group


def test_apply_matches_matrix_multiply():
    coord = (1, 2, 3)
    for i in range(len(R.ROTATIONS)):
        m = R.ROTATIONS[i]
        expected = tuple(sum(m[r][c] * coord[c] for c in range(3)) for r in range(3))
        assert R.apply(i, coord) == expected


def test_rotations_preserve_distance_from_origin():
    coord = (1, 2, 3)
    norm2 = sum(v * v for v in coord)
    for i in range(len(R.ROTATIONS)):
        out = R.apply(i, coord)
        assert sum(v * v for v in out) == norm2


def test_canonical_orbit_is_rotation_and_translation_invariant():
    piece = frozenset({(0, 0, 0), (1, 0, 0), (1, 1, 0), (1, 1, 1)})  # an L-ish tetromino
    base = R.canonical_orbit(piece)
    # rotating then translating must not change the canonical orbit
    for i in range(len(R.ROTATIONS)):
        rotated = R.apply_set(i, piece)
        shifted = frozenset((x + 5, y - 3, z + 2) for x, y, z in rotated)
        assert R.canonical_orbit(shifted) == base
    # idempotence
    assert R.canonical_orbit(base) == base


def test_distinct_shapes_have_distinct_orbits():
    a = frozenset({(0, 0, 0), (1, 0, 0), (2, 0, 0), (3, 0, 0)})   # straight tetromino
    b = frozenset({(0, 0, 0), (1, 0, 0), (1, 1, 0), (1, 1, 1)})   # bent
    assert R.canonical_orbit(a) != R.canonical_orbit(b)
