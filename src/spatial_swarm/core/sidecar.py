"""Private sidecar implementation."""

from __future__ import annotations

import base64
from typing import Optional

from nacl.public import PublicKey, SealedBox
from nacl.signing import SigningKey

from spatial_swarm.core.message import FrozenMessage
from spatial_swarm.crypto.commitments import (
    fragment_commitment,
    normalize_coords,
    proof_commitment,
)
from spatial_swarm.crypto.signatures import sign_payload
from spatial_swarm.geometry.fragment import Fragment
from spatial_swarm.protocol.challenge import Challenge
from spatial_swarm.protocol.policies import ProofEnvelope
from spatial_swarm.protocol.proof_packet import FragmentResponse, ProofPacket


class Sidecar:
    """Holds a private fragment and signing key outside the logical agent."""

    def __init__(
        self,
        fragment: Fragment,
        signing_key: SigningKey,
        gateway_public_key: PublicKey,
        epoch: str,
        envelope: ProofEnvelope,
    ) -> None:
        self.fragment = fragment
        self.signing_key = signing_key
        self.gateway_public_key = gateway_public_key
        self.epoch = epoch
        self.envelope = envelope
        self.agent_id = fragment.agent_id
        self.fragment_commitment = fragment_commitment(fragment.agent_id, fragment.coords, fragment.p)

    @property
    def verify_key(self):
        return self.signing_key.verify_key

    def health_check(self) -> dict[str, str]:
        return {"status": "ok", "agent_id": self.agent_id}

    def submit_proof(
        self,
        message: FrozenMessage,
        challenge: Challenge,
        submission_number: int = 1,
        submitted_at_ms: float = 0.0,
        override_message_id: Optional[str] = None,
        override_challenge_id: Optional[str] = None,
    ) -> ProofPacket:
        return self.build_proof(
            message=message,
            challenge=challenge,
            submission_number=submission_number,
            submitted_at_ms=submitted_at_ms,
            override_message_id=override_message_id,
            override_challenge_id=override_challenge_id,
        )

    def rotate_epoch(self, epoch: str, envelope: Optional[ProofEnvelope] = None) -> None:
        self.epoch = epoch
        if envelope is not None:
            self.envelope = envelope

    def shutdown(self) -> None:
        pass

    def build_proof(
        self,
        message: FrozenMessage,
        challenge: Challenge,
        submission_number: int = 1,
        submitted_at_ms: float = 0.0,
        override_message_id: Optional[str] = None,
        override_challenge_id: Optional[str] = None,
    ) -> ProofPacket:
        transformed = challenge.transform.apply(self.fragment.coords)
        message_id = override_message_id or message.message_id
        challenge_id = override_challenge_id or challenge.challenge_id
        response = FragmentResponse(
            agent_id=self.agent_id,
            message_id=message_id,
            challenge_id=challenge_id,
            fragment_commitment=self.fragment_commitment,
            coords=normalize_coords(transformed),
        )
        plaintext = response.model_dump_json().encode("utf-8")
        encrypted = SealedBox(self.gateway_public_key).encrypt(plaintext)
        encrypted_b64 = base64.b64encode(encrypted).decode("ascii")
        fields = {
            "agent_id": self.agent_id,
            "epoch": self.epoch,
            "message_id": message_id,
            "challenge_id": challenge_id,
            "proof_version": "v1",
            "submission_number": submission_number,
            "proof_commitment": proof_commitment(
                self.agent_id,
                message_id,
                challenge_id,
                transformed,
            ),
            "encrypted_fragment_response": encrypted_b64,
            "signature": "",
            "submitted_at_ms": submitted_at_ms,
        }
        packet = ProofPacket(**fields)
        fields["signature"] = sign_payload(self.signing_key, packet.signed_payload())
        return ProofPacket(**fields)
