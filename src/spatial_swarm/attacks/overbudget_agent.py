"""Over-budget proof attack."""

from __future__ import annotations

from spatial_swarm.core.gateway import Gateway
from spatial_swarm.core.message import FrozenMessage
from spatial_swarm.protocol.challenge import Challenge
from spatial_swarm.protocol.proof_packet import ProofPacket


class OverBudgetAgent:
    def __init__(self, agent_id: str, extra_bytes: int = 50_000):
        self.agent_id = agent_id
        self.extra_bytes = extra_bytes

    def replace_agent_packets(
        self,
        gateway: Gateway,
        message: FrozenMessage,
        challenge: Challenge,
    ) -> list[ProofPacket]:
        packets = gateway.collect_honest_packets(message, challenge)
        mutated: list[ProofPacket] = []
        for packet in packets:
            if packet.agent_id == self.agent_id:
                fields = packet.as_dict()
                fields["encrypted_fragment_response"] = fields["encrypted_fragment_response"] + (
                    "A" * self.extra_bytes
                )
                mutated.append(ProofPacket(**fields))
            else:
                mutated.append(packet)
        return mutated


class UnderBudgetAgent:
    def __init__(self, agent_id: str):
        self.agent_id = agent_id

    def replace_agent_packets(
        self,
        gateway: Gateway,
        message: FrozenMessage,
        challenge: Challenge,
    ) -> list[ProofPacket]:
        packets = gateway.collect_honest_packets(message, challenge)
        mutated: list[ProofPacket] = []
        for packet in packets:
            if packet.agent_id == self.agent_id:
                fields = packet.as_dict()
                fields["encrypted_fragment_response"] = ""
                fields["proof_commitment"] = ""
                fields["signature"] = ""
                mutated.append(ProofPacket(**fields))
            else:
                mutated.append(packet)
        return mutated
