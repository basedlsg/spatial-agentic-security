"""Fake-agent packet generation."""

from __future__ import annotations

import base64
import random
from typing import Any

from nacl.public import SealedBox
from nacl.signing import SigningKey

from spatial_swarm.core.gateway import Gateway
from spatial_swarm.core.message import FrozenMessage
from spatial_swarm.crypto.commitments import proof_commitment
from spatial_swarm.crypto.hashing import hash_bytes
from spatial_swarm.crypto.signatures import sign_payload
from spatial_swarm.protocol.challenge import Challenge
from spatial_swarm.protocol.proof_packet import FragmentResponse, ProofPacket


class RandomFakeAgent:
    """Impersonates a registered agent ID without that agent's signing key or fragment."""

    def __init__(self, agent_id: str, seed: int = 9001):
        self.agent_id = agent_id
        self.seed = seed
        self.signing_key = SigningKey(hash_bytes("fake-agent-key", seed, agent_id)[:32])

    def packet(self, gateway: Gateway, message: FrozenMessage, challenge: Challenge) -> ProofPacket:
        registration = gateway.registry.require(self.agent_id)
        rng = random.Random(self.seed)
        coords = [
            [rng.randrange(gateway.grid.p), rng.randrange(gateway.grid.p), rng.randrange(gateway.grid.p)]
            for _ in range(registration.fragment.size)
        ]
        response = FragmentResponse(
            agent_id=self.agent_id,
            message_id=message.message_id,
            challenge_id=challenge.challenge_id,
            fragment_commitment=registration.fragment_commitment,
            coords=coords,
        )
        encrypted = SealedBox(gateway.private_key.public_key).encrypt(
            response.model_dump_json().encode("utf-8")
        )
        fields: dict[str, Any] = {
            "agent_id": self.agent_id,
            "epoch": gateway.epoch,
            "message_id": message.message_id,
            "challenge_id": challenge.challenge_id,
            "proof_version": "v1",
            "submission_number": 1,
            "proof_commitment": proof_commitment(
                self.agent_id,
                message.message_id,
                challenge.challenge_id,
                {(x, y, z) for x, y, z in response.coords},
            ),
            "encrypted_fragment_response": base64.b64encode(encrypted).decode("ascii"),
            "signature": "",
            "submitted_at_ms": 0.0,
        }
        packet = ProofPacket(**fields)
        fields["signature"] = sign_payload(self.signing_key, packet.signed_payload())
        return ProofPacket(**fields)

    def replace_agent_packets(
        self,
        gateway: Gateway,
        message: FrozenMessage,
        challenge: Challenge,
    ) -> list[ProofPacket]:
        packets = gateway.collect_honest_packets(message, challenge)
        return [self.packet(gateway, message, challenge) if p.agent_id == self.agent_id else p for p in packets]
