"""Finite 3D grid and modular linear algebra."""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

Coord = tuple[int, int, int]


@dataclass(frozen=True)
class FiniteGrid:
    """A finite 3D coordinate space over F_p."""

    p: int = 257

    def validate_coord(self, coord: Coord) -> None:
        if len(coord) != 3:
            raise ValueError("coordinate must be 3-dimensional")
        if any(not 0 <= int(v) < self.p for v in coord):
            raise ValueError(f"coordinate {coord!r} outside F_{self.p}^3")

    def normalize_coord(self, coord: Coord) -> Coord:
        x, y, z = coord
        return (int(x) % self.p, int(y) % self.p, int(z) % self.p)


def det3_mod(matrix: np.ndarray, p: int) -> int:
    a = matrix.astype(int)
    det = (
        a[0, 0] * (a[1, 1] * a[2, 2] - a[1, 2] * a[2, 1])
        - a[0, 1] * (a[1, 0] * a[2, 2] - a[1, 2] * a[2, 0])
        + a[0, 2] * (a[1, 0] * a[2, 1] - a[1, 1] * a[2, 0])
    )
    return int(det % p)


def matrix_inverse_mod(matrix: np.ndarray, p: int) -> np.ndarray:
    a = matrix.astype(int) % p
    det = det3_mod(a, p)
    if det == 0:
        raise ValueError("matrix is not invertible over finite field")

    inv_det = pow(det, -1, p)
    cofactors = np.array(
        [
            [
                a[1, 1] * a[2, 2] - a[1, 2] * a[2, 1],
                -(a[1, 0] * a[2, 2] - a[1, 2] * a[2, 0]),
                a[1, 0] * a[2, 1] - a[1, 1] * a[2, 0],
            ],
            [
                -(a[0, 1] * a[2, 2] - a[0, 2] * a[2, 1]),
                a[0, 0] * a[2, 2] - a[0, 2] * a[2, 0],
                -(a[0, 0] * a[2, 1] - a[0, 1] * a[2, 0]),
            ],
            [
                a[0, 1] * a[1, 2] - a[0, 2] * a[1, 1],
                -(a[0, 0] * a[1, 2] - a[0, 2] * a[1, 0]),
                a[0, 0] * a[1, 1] - a[0, 1] * a[1, 0],
            ],
        ],
        dtype=int,
    )
    adjugate = cofactors.T
    return (inv_det * adjugate) % p


def assert_invertible(matrix: np.ndarray, p: int) -> None:
    inverse = matrix_inverse_mod(matrix, p)
    identity = (matrix.astype(int) @ inverse.astype(int)) % p
    if not np.array_equal(identity, np.eye(3, dtype=int) % p):
        raise ValueError("matrix inverse check failed")
