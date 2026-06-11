"""Fragment generation and representation."""

from __future__ import annotations

import random
from dataclasses import dataclass

from spatial_swarm.geometry.finite_grid import Coord, FiniteGrid


@dataclass(frozen=True)
class Fragment:
    agent_id: str
    coords: set[Coord]
    p: int

    @property
    def size(self) -> int:
        return len(self.coords)


def agent_id_for(index: int) -> str:
    return f"agent_{index:03d}"


def generate_disjoint_fragments(
    agent_count: int,
    fragment_size: int,
    seed: int,
    grid: FiniteGrid,
) -> dict[str, Fragment]:
    if agent_count <= 0:
        raise ValueError("agent_count must be positive")
    if fragment_size <= 0:
        raise ValueError("fragment_size must be positive")
    total = agent_count * fragment_size
    capacity = grid.p**3
    if total > capacity:
        raise ValueError("requested fragments exceed grid capacity")

    full_puzzle = generate_full_puzzle(total, seed, grid)
    return cut_puzzle(full_puzzle, agent_count, fragment_size, grid.p)


def generate_full_puzzle(point_count: int, seed: int, grid: FiniteGrid) -> set[Coord]:
    if point_count <= 0:
        raise ValueError("point_count must be positive")
    if point_count > grid.p**3:
        raise ValueError("requested puzzle exceeds grid capacity")

    rng = random.Random(seed)
    coords: set[Coord] = set()
    while len(coords) < point_count:
        coords.add((rng.randrange(grid.p), rng.randrange(grid.p), rng.randrange(grid.p)))
    return coords


def cut_puzzle(
    full_puzzle: set[Coord],
    agent_count: int,
    fragment_size: int,
    p: int,
) -> dict[str, Fragment]:
    if agent_count <= 0:
        raise ValueError("agent_count must be positive")
    if fragment_size <= 0:
        raise ValueError("fragment_size must be positive")
    total = agent_count * fragment_size
    if len(full_puzzle) != total:
        raise ValueError("full_puzzle size must equal agent_count * fragment_size")
    ordered = sorted(full_puzzle)
    fragments: dict[str, Fragment] = {}
    for index in range(agent_count):
        agent_id = agent_id_for(index + 1)
        start = index * fragment_size
        end = start + fragment_size
        fragments[agent_id] = Fragment(agent_id=agent_id, coords=set(ordered[start:end]), p=p)
    return fragments
