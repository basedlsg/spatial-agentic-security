"""Placeholder interface for future LLM attacker experiments.

This module deliberately does not call any model. The protocol simulator records the
fields that a future Inspect AI or promptfoo harness must provide.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class LLMAttackerAttempt:
    model: str
    provider: str
    prompt: str
    temperature: float
    max_tokens: int
    output: str
    output_tokens: Optional[int]
    latency_ms: Optional[float]
    parse_result: str
    failure_reason: str
