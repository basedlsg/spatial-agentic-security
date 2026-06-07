"""Single stolen fragment and partial-swarm attacks."""

from __future__ import annotations

from spatial_swarm.core.gateway import Gateway
from spatial_swarm.core.message import FrozenMessage
from spatial_swarm.protocol.challenge import Challenge
from spatial_swarm.protocol.proof_packet import ProofPacket


class StolenSinglePieceAgent:
    """Submits one valid sidecar proof but cannot satisfy unanimous assembly."""

    def __init__(self, agent_id: str):
        self.agent_id = agent_id

    def packets(
        self,
        gateway: Gateway,
        message: FrozenMessage,
        challenge: Challenge,
    ) -> list[ProofPacket]:
        return [gateway.sidecars[self.agent_id].build_proof(message, challenge)]


class PartialSwarmAgent:
    def __init__(self, controlled_count: int):
        self.controlled_count = controlled_count

    def packets(
        self,
        gateway: Gateway,
        message: FrozenMessage,
        challenge: Challenge,
    ) -> list[ProofPacket]:
        agent_ids = list(gateway.registry.original_agent_ids)[: self.controlled_count]
        return [gateway.sidecars[agent_id].build_proof(message, challenge) for agent_id in agent_ids]
