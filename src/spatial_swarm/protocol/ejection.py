"""Ejection records."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Ejection:
    agent_id: Optional[str]
    reason: str
    message_id: str
    challenge_id: str
