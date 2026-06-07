"""Late packet attack."""

from __future__ import annotations

from spatial_swarm.core.gateway import Gateway
from spatial_swarm.core.message import FrozenMessage
from spatial_swarm.protocol.challenge import Challenge
from spatial_swarm.protocol.proof_packet import ProofPacket


class SlowAgent:
    def __init__(self, agent_id: str):
        self.agent_id = agent_id

    def replace_agent_packets(
        self,
        gateway: Gateway,
        message: FrozenMessage,
        challenge: Challenge,
    ) -> list[ProofPacket]:
        packets = gateway.collect_honest_packets(message, challenge)
        timeout = gateway.registry.require(self.agent_id).envelope.timeout_ms
        delayed = gateway.sidecars[self.agent_id].build_proof(
            message,
            challenge,
            submitted_at_ms=timeout + 1.0,
        )
        return [delayed if p.agent_id == self.agent_id else p for p in packets]
