"""Duplicate submission attack."""

from __future__ import annotations

from spatial_swarm.core.gateway import Gateway
from spatial_swarm.core.message import FrozenMessage
from spatial_swarm.protocol.challenge import Challenge
from spatial_swarm.protocol.proof_packet import ProofPacket


class DuplicateAgent:
    def __init__(self, agent_id: str):
        self.agent_id = agent_id

    def packets(
        self,
        gateway: Gateway,
        message: FrozenMessage,
        challenge: Challenge,
    ) -> list[ProofPacket]:
        packets = gateway.collect_honest_packets(message, challenge)
        duplicate = gateway.sidecars[self.agent_id].build_proof(message, challenge)
        return packets + [duplicate]
