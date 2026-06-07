"""Message-bound affine transforms over a finite 3D grid."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Union

import numpy as np

from spatial_swarm.crypto.hashing import hash_bytes, sha256_hex
from spatial_swarm.geometry.finite_grid import Coord, det3_mod, matrix_inverse_mod


@dataclass(frozen=True)
class AffineTransform:
    p: int
    matrix: np.ndarray
    translation: tuple[int, int, int]

    def apply_coord(self, coord: Coord) -> Coord:
        vector = np.array(coord, dtype=int)
        out = (self.matrix.astype(int) @ vector + np.array(self.translation, dtype=int)) % self.p
        return (int(out[0]), int(out[1]), int(out[2]))

    def apply(self, coords: Union[set[Coord], list[Coord], tuple[Coord, ...]]) -> set[Coord]:
        return {self.apply_coord(coord) for coord in coords}

    def inverse(self) -> "AffineTransform":
        inv_matrix = matrix_inverse_mod(self.matrix, self.p)
        translation = tuple(int(v) for v in ((-inv_matrix @ np.array(self.translation)) % self.p))
        return AffineTransform(p=self.p, matrix=inv_matrix, translation=translation)

    def fingerprint(self) -> str:
        return sha256_hex(
            {
                "p": self.p,
                "matrix": self.matrix.astype(int).tolist(),
                "translation": list(self.translation),
            }
        )


def transform_from_challenge(challenge_id: str, p: int) -> AffineTransform:
    counter = 0
    while True:
        seed = hash_bytes("usag-transform-matrix", challenge_id, counter)
        values = [byte % p for byte in seed[:9]]
        matrix = np.array(values, dtype=int).reshape(3, 3)
        if det3_mod(matrix, p) != 0:
            break
        counter += 1

    translation_seed = hash_bytes("usag-transform-translation", challenge_id)
    translation = tuple(int(byte % p) for byte in translation_seed[:3])
    return AffineTransform(p=p, matrix=matrix, translation=translation)  # type: ignore[arg-type]
