"""Observation generator for Lab A: a piece seen under hidden rigid poses.

The attacker receives only the transformed coordinate sets g_i(P); the poses g_i
and the canonical piece P are never returned.
"""

from __future__ import annotations

import random

from spatial_swarm.spatial_lab.pose import RigidPose, apply_pose, random_pose

Coord = tuple[int, int, int]


def observe(piece, rng: random.Random, count: int, bound: int) -> list[frozenset[Coord]]:
    """Return `count` views of `piece`, each under an independent hidden pose."""

    return [apply_pose(random_pose(rng, bound), piece) for _ in range(count)]


def observe_with_poses(
    piece, rng: random.Random, count: int, bound: int
) -> list[tuple[RigidPose, frozenset[Coord]]]:
    """Lab-internal variant exposing the hidden poses (for tests/ground truth only)."""

    out = []
    for _ in range(count):
        g = random_pose(rng, bound)
        out.append((g, apply_pose(g, piece)))
    return out
