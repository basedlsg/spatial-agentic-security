"""What the attacker sees, and the attacker-computable clue predicate.

A PublicView never contains a raw piece (except deliberately-revealed neighbors at
O3/O4) and never the exact connector signature -- only lossy projections. The clue
predicate is what an attacker uses to prune candidate pieces; it is built only from
attacker-computable public projections.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from spatial_swarm.spatial_puzzle.generators.polycube import connector_histogram, topology_band

Coord = tuple[int, int, int]


@dataclass(frozen=True)
class HiddenSolution:
    repr_name: str
    swarm_id: str
    n: int
    k: int
    target: frozenset
    pieces: dict[str, frozenset]
    commitments: dict[str, str]
    alphabet_size: int
    topo_bucket: int
    asymmetric: dict[str, bool] = field(default_factory=dict)
    cavity: dict[str, bool] = field(default_factory=dict)

    def agent_ids(self) -> list[str]:
        return sorted(self.pieces)


@dataclass(frozen=True)
class PublicView:
    repr_name: str
    swarm_id: str
    k: int
    agent: str
    commitment: str
    outer_shape: Optional[frozenset]
    revealed_pieces: dict[str, frozenset]
    connector_hist: Optional[tuple]
    topology_band_value: Optional[tuple]
    alphabet_size: int
    topo_bucket: int


def region_for(view: PublicView) -> frozenset:
    """Cells the unknown piece must come from: outer shape minus revealed neighbors."""

    if view.outer_shape is None:
        return frozenset()
    revealed = (
        frozenset().union(*view.revealed_pieces.values()) if view.revealed_pieces else frozenset()
    )
    return frozenset(view.outer_shape) - revealed


def clue_predicate_for(view: PublicView) -> Callable[[frozenset], bool]:
    target = view.outer_shape

    def predicate(cand: frozenset) -> bool:
        if view.connector_hist is not None and target is not None:
            if connector_histogram(cand, target, view.alphabet_size) != view.connector_hist:
                return False
        if view.topology_band_value is not None:
            if topology_band(cand, view.topo_bucket) != view.topology_band_value:
                return False
        return True

    return predicate
