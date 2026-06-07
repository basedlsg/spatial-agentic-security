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

    rng = random.Random(seed)
    coords: set[Coord] = set()
    while len(coords) < total:
        coords.add((rng.randrange(grid.p), rng.randrange(grid.p), rng.randrange(grid.p)))

    ordered = sorted(coords)
    fragments: dict[str, Fragment] = {}
    for index in range(agent_count):
        agent_id = agent_id_for(index + 1)
        start = index * fragment_size
        end = start + fragment_size
        fragments[agent_id] = Fragment(agent_id=agent_id, coords=set(ordered[start:end]), p=grid.p)
    return fragments
