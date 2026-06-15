"""The proper rotation group of the cube: 24 integer matrices (det = +1).

A 3D voxel/point piece is "rotatable": its identity is its rotation orbit's
canonical representative. An attacker reasoning about pieces, and a registration
solver inverting an unknown pose, both work over this group.
"""

from __future__ import annotations

from itertools import permutations, product

Coord = tuple[int, int, int]
Matrix = tuple[tuple[int, int, int], tuple[int, int, int], tuple[int, int, int]]


def _det3(m: Matrix) -> int:
    (a, b, c), (d, e, f), (g, h, i) = m
    return a * (e * i - f * h) - b * (d * i - f * g) + c * (d * h - e * g)


def _signed_permutation_matrices() -> list[Matrix]:
    mats: list[Matrix] = []
    for perm in permutations(range(3)):
        for signs in product((1, -1), repeat=3):
            rows = []
            for axis in range(3):
                row = [0, 0, 0]
                row[perm[axis]] = signs[axis]
                rows.append(tuple(row))
            mats.append((rows[0], rows[1], rows[2]))
    return mats


# The 24 proper rotations (det == +1) of the 48 signed permutation matrices.
ROTATIONS: tuple[Matrix, ...] = tuple(m for m in _signed_permutation_matrices() if _det3(m) == 1)

IDENTITY_INDEX: int = ROTATIONS.index(((1, 0, 0), (0, 1, 0), (0, 0, 1)))

_INDEX: dict[Matrix, int] = {m: i for i, m in enumerate(ROTATIONS)}


def apply(rot_index: int, coord: Coord) -> Coord:
    m = ROTATIONS[rot_index]
    x, y, z = coord
    return (
        m[0][0] * x + m[0][1] * y + m[0][2] * z,
        m[1][0] * x + m[1][1] * y + m[1][2] * z,
        m[2][0] * x + m[2][1] * y + m[2][2] * z,
    )


def apply_set(rot_index: int, coords) -> frozenset[Coord]:
    return frozenset(apply(rot_index, c) for c in coords)


def _matmul(a: Matrix, b: Matrix) -> Matrix:
    return tuple(  # type: ignore[return-value]
        tuple(sum(a[i][k] * b[k][j] for k in range(3)) for j in range(3)) for i in range(3)
    )


def compose(i: int, j: int) -> int:
    """Index of ROTATIONS[i] @ ROTATIONS[j]."""

    return _INDEX[_matmul(ROTATIONS[i], ROTATIONS[j])]


def inverse(i: int) -> int:
    """Index of the inverse rotation (the transpose, since rotations are orthogonal)."""

    m = ROTATIONS[i]
    transpose: Matrix = (
        (m[0][0], m[1][0], m[2][0]),
        (m[0][1], m[1][1], m[2][1]),
        (m[0][2], m[1][2], m[2][2]),
    )
    return _INDEX[transpose]


def normalize_to_origin(coords) -> frozenset[Coord]:
    """Translate a coordinate set so its per-axis minimum sits at the origin."""

    pts = list(coords)
    if not pts:
        return frozenset()
    mx = min(p[0] for p in pts)
    my = min(p[1] for p in pts)
    mz = min(p[2] for p in pts)
    return frozenset((p[0] - mx, p[1] - my, p[2] - mz) for p in pts)


def _sort_key(coords: frozenset[Coord]) -> tuple[Coord, ...]:
    return tuple(sorted(coords))


def canonical_orbit(coords) -> frozenset[Coord]:
    """The rotation-and-translation invariant representative of a piece.

    The lexicographically minimal origin-normalized image over the 24 rotations.
    Two pieces are equal up to rotation+translation iff their canonical orbits match.
    """

    best: frozenset[Coord] | None = None
    best_key: tuple[Coord, ...] | None = None
    for r in range(len(ROTATIONS)):
        candidate = normalize_to_origin(apply_set(r, coords))
        key = _sort_key(candidate)
        if best_key is None or key < best_key:
            best, best_key = candidate, key
    return best if best is not None else frozenset()
