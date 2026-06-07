"""Logical protocol agent with no direct peer communication API."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class LogicalAgent:
    agent_id: str
    gateway: Any

    def request_send(self, receiver_id: str, content: Any):
        return self.gateway.send(self.agent_id, receiver_id, content)
