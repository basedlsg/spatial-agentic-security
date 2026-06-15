"""Rigid poses for Lab A: a cube rotation plus a bounded-lattice translation.

This is a *physical* rigid motion on the integer lattice, distinct from the
protocol's wrap-around affine transform. An attacker that observes a piece under a
hidden pose must search this finite pose space; its size (24 x (2b+1)^3) is printed
next to solver time so a large finite search is never misread as cryptographic
hardness.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from spatial_swarm.spatial_lab.rotations import apply, apply_set, inverse

Coord = tuple[int, int, int]


@dataclass(frozen=True)
class RigidPose:
    rot_index: int
    translation: Coord


def apply_pose(pose: RigidPose, coords) -> frozenset[Coord]:
    tx, ty, tz = pose.translation
    return frozenset(
        (x + tx, y + ty, z + tz) for (x, y, z) in apply_set(pose.rot_index, coords)
    )


def inverse_pose(pose: RigidPose) -> RigidPose:
    inv_rot = inverse(pose.rot_index)
    nt = apply(inv_rot, (-pose.translation[0], -pose.translation[1], -pose.translation[2]))
    return RigidPose(inv_rot, nt)


def translation_grid(bound: int) -> list[Coord]:
    return [
        (dx, dy, dz)
        for dx in range(-bound, bound + 1)
        for dy in range(-bound, bound + 1)
        for dz in range(-bound, bound + 1)
    ]


def pose_space_size(bound: int) -> int:
    return 24 * (2 * bound + 1) ** 3


def random_pose(rng: random.Random, bound: int) -> RigidPose:
    return RigidPose(
        rot_index=rng.randrange(24),
        translation=(
            rng.randint(-bound, bound),
            rng.randint(-bound, bound),
            rng.randint(-bound, bound),
        ),
    )
