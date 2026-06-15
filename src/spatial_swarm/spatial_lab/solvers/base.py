"""Shared solver types: a time/node budget and a uniform result record.

`budget_hit` (stopped on the budget) and `exhausted` (search space provably
emptied) are distinct: an exact candidate count is trustworthy only when
`exhausted and not budget_hit`. A solver never reports `found` on a budget stop.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Optional


class Budget:
    def __init__(self, max_seconds: float = 5.0, max_nodes: int = 2_000_000):
        self.max_seconds = max_seconds
        self.max_nodes = max_nodes
        self._t0 = time.perf_counter()

    def reset(self) -> None:
        self._t0 = time.perf_counter()

    def elapsed(self) -> float:
        return time.perf_counter() - self._t0

    def tripped(self, nodes: int) -> bool:
        return nodes >= self.max_nodes or self.elapsed() >= self.max_seconds


@dataclass
class SolverResult:
    found: bool
    nodes_expanded: int
    guesses: int
    wall_seconds: float
    budget_hit: bool
    exhausted: bool
    recovered: Optional[frozenset] = None     # in-lab only; never serialized raw
    consistent_candidates: Optional[int] = None  # constraint-consistent count (Lab B)
    pose_space_size: Optional[int] = None        # searched pose space (Lab A)
    method: str = ""

    def public_dict(self) -> dict:
        """Loggable view: never includes the raw recovered secret."""

        return {
            "method": self.method,
            "found": self.found,
            "nodes_expanded": self.nodes_expanded,
            "guesses": self.guesses,
            "wall_seconds": self.wall_seconds,
            "budget_hit": self.budget_hit,
            "exhausted": self.exhausted,
            "consistent_candidates": self.consistent_candidates,
            "pose_space_size": self.pose_space_size,
        }
