"""Wrong-message attack."""

from __future__ import annotations

from spatial_swarm.core.gateway import Gateway
from spatial_swarm.core.message import FrozenMessage
from spatial_swarm.protocol.challenge import Challenge
from spatial_swarm.protocol.proof_packet import ProofPacket


class WrongMessageAgent:
    def packets_for_other_message(
        self,
        gateway: Gateway,
        other_message: FrozenMessage,
        other_challenge: Challenge,
    ) -> list[ProofPacket]:
        return gateway.collect_honest_packets(other_message, other_challenge)
