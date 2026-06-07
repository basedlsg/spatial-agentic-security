"""Attacks with valid signing authority but invalid spatial proof material."""

from __future__ import annotations

import base64
from typing import Any

from nacl.public import SealedBox

from spatial_swarm.core.gateway import Gateway
from spatial_swarm.core.message import FrozenMessage
from spatial_swarm.crypto.commitments import normalize_coords, proof_commitment
from spatial_swarm.crypto.signatures import sign_payload
from spatial_swarm.protocol.challenge import Challenge
from spatial_swarm.protocol.proof_packet import FragmentResponse, ProofPacket


class ValidSignatureWrongGeometryAgent:
    """Uses the target agent's signing key but submits the wrong spatial coordinates."""

    def __init__(self, target_agent_id: str, source_agent_id: str) -> None:
        self.target_agent_id = target_agent_id
        self.source_agent_id = source_agent_id

    def replace_agent_packets(
        self,
        gateway: Gateway,
        message: FrozenMessage,
        challenge: Challenge,
    ) -> list[ProofPacket]:
        packets = gateway.collect_honest_packets(message, challenge)
        malicious = self.packet(gateway, message, challenge)
        return [malicious if packet.agent_id == self.target_agent_id else packet for packet in packets]

    def packet(
        self,
        gateway: Gateway,
        message: FrozenMessage,
        challenge: Challenge,
    ) -> ProofPacket:
        target_registration = gateway.registry.require(self.target_agent_id)
        source_registration = gateway.registry.require(self.source_agent_id)
        wrong_coords = challenge.transform.apply(source_registration.fragment.coords)
        response = FragmentResponse(
            agent_id=self.target_agent_id,
            message_id=message.message_id,
            challenge_id=challenge.challenge_id,
            fragment_commitment=target_registration.fragment_commitment,
            coords=normalize_coords(wrong_coords),
        )
        encrypted = SealedBox(gateway.private_key.public_key).encrypt(
            response.model_dump_json().encode("utf-8")
        )
        fields: dict[str, Any] = {
            "agent_id": self.target_agent_id,
            "epoch": gateway.epoch,
            "message_id": message.message_id,
            "challenge_id": challenge.challenge_id,
            "proof_version": "v1",
            "submission_number": 1,
            "proof_commitment": proof_commitment(
                self.target_agent_id,
                message.message_id,
                challenge.challenge_id,
                wrong_coords,
            ),
            "encrypted_fragment_response": base64.b64encode(encrypted).decode("ascii"),
            "signature": "",
            "submitted_at_ms": 0.0,
        }
        unsigned = ProofPacket(**fields)
        fields["signature"] = sign_payload(
            gateway.sidecars[self.target_agent_id].signing_key,
            unsigned.signed_payload(),
        )
        return ProofPacket(**fields)


class ValidSignatureWrongTransformAgent(ValidSignatureWrongGeometryAgent):
    """Uses valid signing authority but coordinates from another message transform."""

    def packet(
        self,
        gateway: Gateway,
        message: FrozenMessage,
        challenge: Challenge,
    ) -> ProofPacket:
        target_registration = gateway.registry.require(self.target_agent_id)
        other_message = gateway.freeze(
            message.sender_id,
            message.receiver_id,
            message.content,
            nonce=f"{message.nonce}:wrong-transform",
        )
        other_challenge = gateway.challenge(other_message)
        wrong_coords = other_challenge.transform.apply(target_registration.fragment.coords)
        response = FragmentResponse(
            agent_id=self.target_agent_id,
            message_id=message.message_id,
            challenge_id=challenge.challenge_id,
            fragment_commitment=target_registration.fragment_commitment,
            coords=normalize_coords(wrong_coords),
        )
        encrypted = SealedBox(gateway.private_key.public_key).encrypt(
            response.model_dump_json().encode("utf-8")
        )
        fields: dict[str, Any] = {
            "agent_id": self.target_agent_id,
            "epoch": gateway.epoch,
            "message_id": message.message_id,
            "challenge_id": challenge.challenge_id,
            "proof_version": "v1",
            "submission_number": 1,
            "proof_commitment": proof_commitment(
                self.target_agent_id,
                message.message_id,
                challenge.challenge_id,
                wrong_coords,
            ),
            "encrypted_fragment_response": base64.b64encode(encrypted).decode("ascii"),
            "signature": "",
            "submitted_at_ms": 0.0,
        }
        unsigned = ProofPacket(**fields)
        fields["signature"] = sign_payload(
            gateway.sidecars[self.target_agent_id].signing_key,
            unsigned.signed_payload(),
        )
        return ProofPacket(**fields)


class ValidSignatureWrongMessageHashAgent(ValidSignatureWrongGeometryAgent):
    """Uses valid signing authority and correct geometry but binds packet to wrong message."""

    def packet(
        self,
        gateway: Gateway,
        message: FrozenMessage,
        challenge: Challenge,
    ) -> ProofPacket:
        target_registration = gateway.registry.require(self.target_agent_id)
        correct_coords = challenge.transform.apply(target_registration.fragment.coords)
        wrong_message_id = "0" * 64
        response = FragmentResponse(
            agent_id=self.target_agent_id,
            message_id=wrong_message_id,
            challenge_id=challenge.challenge_id,
            fragment_commitment=target_registration.fragment_commitment,
            coords=normalize_coords(correct_coords),
        )
        encrypted = SealedBox(gateway.private_key.public_key).encrypt(
            response.model_dump_json().encode("utf-8")
        )
        fields: dict[str, Any] = {
            "agent_id": self.target_agent_id,
            "epoch": gateway.epoch,
            "message_id": wrong_message_id,
            "challenge_id": challenge.challenge_id,
            "proof_version": "v1",
            "submission_number": 1,
            "proof_commitment": proof_commitment(
                self.target_agent_id,
                wrong_message_id,
                challenge.challenge_id,
                correct_coords,
            ),
            "encrypted_fragment_response": base64.b64encode(encrypted).decode("ascii"),
            "signature": "",
            "submitted_at_ms": 0.0,
        }
        unsigned = ProofPacket(**fields)
        fields["signature"] = sign_payload(
            gateway.sidecars[self.target_agent_id].signing_key,
            unsigned.signed_payload(),
        )
        return ProofPacket(**fields)
