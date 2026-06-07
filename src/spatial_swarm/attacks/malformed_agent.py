"""Malformed packet attack."""

from __future__ import annotations

from typing import Any

from spatial_swarm.core.gateway import Gateway
from spatial_swarm.core.message import FrozenMessage
from spatial_swarm.protocol.challenge import Challenge


class MalformedAgent:
    def __init__(self, agent_id: str):
        self.agent_id = agent_id

    def packets(self, gateway: Gateway, message: FrozenMessage, challenge: Challenge) -> list[dict[str, Any]]:
        return [
            {
                "agent_id": self.agent_id,
                "epoch": gateway.epoch,
                "message_id": message.message_id,
                "challenge_id": challenge.challenge_id,
                "proof_version": "v1",
            }
        ]
