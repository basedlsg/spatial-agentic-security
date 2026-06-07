"""Epoch and swarm lifecycle state."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class SwarmState(str, Enum):
    ACTIVE = "ACTIVE"
    COLLAPSED = "COLLAPSED"


@dataclass(frozen=True)
class Epoch:
    index: int

    @property
    def epoch_id(self) -> str:
        return f"epoch_{self.index:04d}"
