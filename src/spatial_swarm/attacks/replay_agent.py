"""Replay attack."""

from __future__ import annotations

from spatial_swarm.protocol.proof_packet import ProofPacket


class ReplayAgent:
    def __init__(self, packets: list[ProofPacket]):
        self.packets = packets

    def packets_for_replay(self) -> list[ProofPacket]:
        return list(self.packets)
