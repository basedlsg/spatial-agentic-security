"""Leakage-bounded spatial construction: sparse pieces in a larger ambient region.

The anti-leak generator SELECTS low-correlation partitions from a pool. This module tests
a DESIGNED construction instead: place the n committed k-pieces sparsely (spread out)
inside a public ambient region larger than their union, so that stealing a neighbor
removes cells far from the target and barely prunes the target's candidate set. The knob
is the sparsity ratio rho = |ambient| / (n*k). Measured question: does the leak (bits lost
from A0 to A3 under stolen neighbors) shrink toward 0 (random-like) as rho grows?

Faithful to the second-factor model: the second factor is a connected k-subset of a public
region; here the region is larger than the union of pieces (unowned filler cells), which is
the design lever. Each construction is measured against a random factor matched to ITS OWN
A0 residual, which loses 0 bits under theft; the metric is the deviation from that.
"""

from __future__ import annotations

import math
import random
from typing import Optional

from spatial_swarm.spatial_lab import commit as C
from spatial_swarm.spatial_lab.shapes import is_connected, neighbors6
from spatial_swarm.spatial_puzzle.experiments import anti_leak
from spatial_swarm.spatial_puzzle.generators.visibility import HiddenSolution


def grow_region(rng: random.Random, size: int, *, max_attempts: int = 200) -> frozenset:
    """A connected blob of `size` cells grown by accretion from the origin."""

    for _ in range(max_attempts):
        cells = {(0, 0, 0)}
        while len(cells) < size:
            frontier = list({nb for c in cells for nb in neighbors6(c) if nb not in cells})
            if not frontier:
                break
            cells.add(frontier[rng.randrange(len(frontier))])
        if len(cells) == size and is_connected(cells):
            return frozenset(cells)
    raise RuntimeError(f"could not grow a connected region of size {size}")


def _dist(a, b) -> int:
    return abs(a[0] - b[0]) + abs(a[1] - b[1]) + abs(a[2] - b[2])


def _farthest_seeds(rng: random.Random, region: frozenset, n: int) -> list:
    """Farthest-point sampling: seeds spread across the region."""

    cells = list(region)
    seeds = [cells[rng.randrange(len(cells))]]
    while len(seeds) < n:
        nxt = max(cells, key=lambda c: min(_dist(c, s) for s in seeds))
        if nxt in seeds:
            break
        seeds.append(nxt)
    return seeds


def _grow_piece(rng: random.Random, region: frozenset, used: set, seed, k: int) -> Optional[frozenset]:
    """Grow a connected k-piece from `seed` within `region`, avoiding `used` cells."""

    if seed in used or seed not in region:
        return None
    piece = {seed}
    while len(piece) < k:
        frontier = [nb for c in piece for nb in neighbors6(c)
                    if nb in region and nb not in used and nb not in piece]
        if not frontier:
            return None
        piece.add(frontier[rng.randrange(len(frontier))])
    return frozenset(piece)


def place_spread_pieces(rng: random.Random, region: frozenset, *, n: int, k: int,
                        max_attempts: int = 60) -> Optional[dict]:
    """Place n disjoint connected k-pieces, spread out (farthest-point seeds)."""

    for _ in range(max_attempts):
        used: set = set()
        seeds = _farthest_seeds(rng, region, n)
        pieces = {}
        ok = True
        for i, seed in enumerate(seeds):
            p = _grow_piece(rng, region, used, seed, k)
            if p is None:
                ok = False
                break
            pieces[f"agent_{i + 1:03d}"] = p
            used |= p
        if ok and len(pieces) == n:
            return pieces
    return None


def build_sparse_solution(rng: random.Random, *, n: int, k: int, ambient_size: int,
                          swarm_id: str, repr_name: str = "SPARSE",
                          max_attempts: int = 40) -> HiddenSolution:
    """A HiddenSolution whose target is the ambient region (>= n*k), pieces placed sparsely."""

    for _ in range(max_attempts):
        region = grow_region(rng, ambient_size)
        pieces = place_spread_pieces(rng, region, n=n, k=k)
        if pieces is not None:
            commitments = {a: C.commit(swarm_id, a, repr_name, p) for a, p in pieces.items()}
            return HiddenSolution(
                repr_name=repr_name, swarm_id=swarm_id, n=n, k=k, target=region,
                pieces=pieces, commitments=commitments, alphabet_size=4, topo_bucket=2,
            )
    raise RuntimeError(f"could not place {n} spread pieces in ambient size {ambient_size}")


def leak_profile(sol: HiddenSolution, *, budget: tuple = (8.0, 3_000_000)) -> dict:
    """A0/worst-A2/worst-A3 residual + bits lost A0->A3 for one solution (reuses anti_leak)."""

    score = anti_leak.score_candidate(sol, budget=budget)
    bits_lost_a2 = (math.log2(score.a0 / score.worst_a2)
                    if (score.enumerated and score.a0 and score.worst_a2) else None)
    bits_lost_a3 = (math.log2(score.a0 / score.worst_a3)
                    if (score.enumerated and score.a0 and score.worst_a3) else None)
    return {
        "enumerated": score.enumerated,
        "ambient_cells": len(sol.target),
        "a0": score.a0,
        "worst_a2": score.worst_a2,
        "worst_a3": score.worst_a3,
        "bits_lost_a0_to_a2": bits_lost_a2,
        "bits_lost_a0_to_a3": bits_lost_a3,
        "neighbor_copy": score.neighbor_copy,
    }
