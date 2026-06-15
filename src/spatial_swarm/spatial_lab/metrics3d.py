"""Reconstruction-error metrics for a recovered piece vs ground truth.

All overlap metrics are pose-aware: the recovered set A is aligned to the truth G
over the 24 cube rotations and all integer translations that match one cell to one
cell, taking the best overlap. A pose-image of G therefore scores 1.0.
"""

from __future__ import annotations

import math

from spatial_swarm.spatial_lab.rotations import ROTATIONS, apply_set, normalize_to_origin
from spatial_swarm.spatial_lab.shapes import surface_area

Coord = tuple[int, int, int]


def _best_intersection(A, G) -> int:
    """Max |A_posed ∩ G| over 24 rotations × all one-cell-to-one-cell translations."""

    A = frozenset(A)
    G = frozenset(G)
    if not A or not G:
        return 0
    best = 0
    seen_rot: set[frozenset] = set()
    for r in range(len(ROTATIONS)):
        An = normalize_to_origin(apply_set(r, A))
        if An in seen_rot:
            continue
        seen_rot.add(An)
        for a in An:
            for g in G:
                sx, sy, sz = g[0] - a[0], g[1] - a[1], g[2] - a[2]
                shifted = frozenset((x + sx, y + sy, z + sz) for x, y, z in An)
                inter = len(shifted & G)
                if inter > best:
                    best = inter
                    if best == len(A):  # cannot do better
                        return best
    return best


def iou(A, G) -> float:
    A, G = frozenset(A), frozenset(G)
    if not A and not G:
        return 1.0
    if not A or not G:
        return 0.0
    inter = _best_intersection(A, G)
    return inter / (len(A) + len(G) - inter)


def dice(A, G) -> float:
    A, G = frozenset(A), frozenset(G)
    if not A and not G:
        return 1.0
    if not A or not G:
        return 0.0
    inter = _best_intersection(A, G)
    return 2 * inter / (len(A) + len(G))


def precision_recall(A, G) -> tuple[float, float]:
    A, G = frozenset(A), frozenset(G)
    if not A or not G:
        return (0.0, 0.0)
    inter = _best_intersection(A, G)
    return (inter / len(A), inter / len(G))


def surface_match(A, G) -> float:
    sa, sg = surface_area(A), surface_area(G)
    if sa == 0 and sg == 0:
        return 1.0
    return 1.0 - abs(sa - sg) / max(sa, sg)


def _centroid(points: list[Coord]) -> tuple[float, float, float]:
    n = len(points)
    return (
        sum(p[0] for p in points) / n,
        sum(p[1] for p in points) / n,
        sum(p[2] for p in points) / n,
    )


def _directed(src: list[Coord], dst: list[Coord], reducer) -> float:
    return reducer(
        min(math.dist(s, d) for d in dst) for s in src
    )


def _best_aligned(A, G):
    """Yield (A_posed_list, G_list) for each rotation, centroid-translation aligned."""

    A = list(A)
    G = list(G)
    gc = _centroid(G)
    for r in range(len(ROTATIONS)):
        An = list(apply_set(r, A))
        ac = _centroid(An)
        sx, sy, sz = round(gc[0] - ac[0]), round(gc[1] - ac[1]), round(gc[2] - ac[2])
        yield [(x + sx, y + sy, z + sz) for x, y, z in An], G


def chamfer_distance(A, G) -> float:
    A, G = list(A), list(G)
    if not A or not G:
        return float("inf")
    best = float("inf")
    for posed, g in _best_aligned(A, G):
        d = _directed(posed, g, _mean) + _directed(g, posed, _mean)
        best = min(best, d)
    return best


def hausdorff_distance(A, G) -> float:
    A, G = list(A), list(G)
    if not A or not G:
        return float("inf")
    best = float("inf")
    for posed, g in _best_aligned(A, G):
        d = max(_directed(posed, g, max), _directed(g, posed, max))
        best = min(best, d)
    return best


def _mean(values) -> float:
    vals = list(values)
    return sum(vals) / len(vals) if vals else 0.0


def reconstruction_error(recovered, truth) -> dict[str, float]:
    return {
        "iou": iou(recovered, truth),
        "dice": dice(recovered, truth),
        "surface_match": surface_match(recovered, truth),
        "chamfer": chamfer_distance(recovered, truth),
        "hausdorff": hausdorff_distance(recovered, truth),
    }
