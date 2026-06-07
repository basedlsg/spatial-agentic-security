"""USAG proof verifier."""

from __future__ import annotations

import base64
import time
from dataclasses import dataclass, field
from typing import Any, Optional, Sequence, Union

from nacl.exceptions import CryptoError
from nacl.public import PrivateKey, SealedBox
from pydantic import ValidationError

from spatial_swarm.core.epoch import SwarmState
from spatial_swarm.core.errors import FailureReason
from spatial_swarm.core.message import FrozenMessage
from spatial_swarm.core.registry import Registry
from spatial_swarm.crypto.commitments import proof_commitment
from spatial_swarm.crypto.signatures import verify_payload
from spatial_swarm.geometry.assembly import assembles_exactly
from spatial_swarm.protocol.challenge import Challenge
from spatial_swarm.protocol.ejection import Ejection
from spatial_swarm.protocol.proof_packet import FragmentResponse, ProofPacket, packet_size_bytes


@dataclass(frozen=True)
class VerificationEvent:
    event_type: str
    agent_id: Optional[str]
    message_id: str
    challenge_id: str
    epoch: str
    valid: bool
    failure_reason: Optional[str] = None
    proof_bytes: Optional[int] = None
    latency_ms: Optional[float] = None
    submission_number: Optional[int] = None

    def to_log_dict(self, run_id: str) -> dict[str, Any]:
        return {
            "run_id": run_id,
            "event_type": self.event_type,
            "agent_id": self.agent_id,
            "message_id": self.message_id,
            "challenge_id": self.challenge_id,
            "epoch": self.epoch,
            "valid": self.valid,
            "failure_reason": self.failure_reason,
            "proof_bytes": self.proof_bytes,
            "latency_ms": self.latency_ms,
            "submission_number": self.submission_number,
        }


@dataclass(frozen=True)
class VerificationResult:
    passed: bool
    released_message: Optional[Any]
    failure_reason: Optional[str]
    ejection: Optional[Ejection]
    collapsed: bool
    latency_ms: float
    proof_bytes_total: int
    events: list[VerificationEvent] = field(default_factory=list)


class Verifier:
    def __init__(self, registry: Registry, private_key: PrivateKey):
        self.registry = registry
        self.private_key = private_key
        self._seen: set[tuple[str, str, str]] = set()

    def verify_round(
        self,
        message: FrozenMessage,
        challenge: Challenge,
        raw_packets: Sequence[Union[ProofPacket, dict[str, Any]]],
    ) -> VerificationResult:
        started = time.perf_counter()
        events: list[VerificationEvent] = []
        proof_bytes_total = 0
        submitted_coords: dict[str, set[tuple[int, int, int]]] = {}
        seen_this_round: set[str] = set()

        def elapsed() -> float:
            return (time.perf_counter() - started) * 1000.0

        def fail(
            reason: FailureReason,
            agent_id: Optional[str],
            proof_bytes: Optional[int] = None,
            submission_number: Optional[int] = None,
        ) -> VerificationResult:
            self.registry.eject(agent_id)
            latency = elapsed()
            ejection = Ejection(
                agent_id=agent_id,
                reason=reason.value,
                message_id=message.message_id,
                challenge_id=challenge.challenge_id,
            )
            events.append(
                VerificationEvent(
                    event_type="proof_failed",
                    agent_id=agent_id,
                    message_id=message.message_id,
                    challenge_id=challenge.challenge_id,
                    epoch=message.epoch,
                    valid=False,
                    failure_reason=reason.value,
                    proof_bytes=proof_bytes,
                    latency_ms=latency,
                    submission_number=submission_number,
                )
            )
            return VerificationResult(
                passed=False,
                released_message=None,
                failure_reason=reason.value,
                ejection=ejection,
                collapsed=True,
                latency_ms=latency,
                proof_bytes_total=proof_bytes_total,
                events=events,
            )

        if self.registry.state != SwarmState.ACTIVE:
            return fail(FailureReason.SWARM_COLLAPSED, None)

        for raw_packet in raw_packets:
            packet: ProofPacket
            if isinstance(raw_packet, ProofPacket):
                packet = raw_packet
            else:
                try:
                    packet = ProofPacket.model_validate(raw_packet)
                except ValidationError:
                    return fail(FailureReason.MALFORMED_PACKET, raw_packet.get("agent_id"))

            agent_id = packet.agent_id
            registration = self.registry.get(agent_id)
            if registration is None:
                return fail(
                    FailureReason.UNREGISTERED_AGENT,
                    agent_id,
                    submission_number=packet.submission_number,
                )
            if not registration.active:
                return fail(
                    FailureReason.INACTIVE_AGENT,
                    agent_id,
                    submission_number=packet.submission_number,
                )
            if packet.epoch != self.registry.epoch:
                return fail(FailureReason.WRONG_EPOCH, agent_id, submission_number=packet.submission_number)
            if packet.message_id != message.message_id:
                return fail(
                    FailureReason.WRONG_MESSAGE_HASH,
                    agent_id,
                    submission_number=packet.submission_number,
                )
            if packet.challenge_id != challenge.challenge_id:
                return fail(
                    FailureReason.WRONG_CHALLENGE,
                    agent_id,
                    submission_number=packet.submission_number,
                )
            if packet.submission_number != 1:
                return fail(
                    FailureReason.INVALID_SUBMISSION_NUMBER,
                    agent_id,
                    submission_number=packet.submission_number,
                )
            seen_key = (agent_id, message.message_id, challenge.challenge_id)
            if agent_id in seen_this_round or seen_key in self._seen:
                size = packet_size_bytes(packet)
                proof_bytes_total += size
                return fail(
                    FailureReason.DUPLICATE_SUBMISSION,
                    agent_id,
                    proof_bytes=size,
                    submission_number=packet.submission_number,
                )
            seen_this_round.add(agent_id)

            size = packet_size_bytes(packet)
            proof_bytes_total += size
            size_state = registration.envelope.validate_size(size)
            if size_state == "over":
                return fail(
                    FailureReason.OVER_BUDGET,
                    agent_id,
                    proof_bytes=size,
                    submission_number=packet.submission_number,
                )
            if size_state == "under":
                return fail(
                    FailureReason.UNDER_BUDGET,
                    agent_id,
                    proof_bytes=size,
                    submission_number=packet.submission_number,
                )
            if packet.submitted_at_ms > registration.envelope.timeout_ms:
                return fail(
                    FailureReason.LATE_PACKET,
                    agent_id,
                    proof_bytes=size,
                    submission_number=packet.submission_number,
                )
            if not verify_payload(registration.verify_key, packet.signed_payload(), packet.signature):
                return fail(
                    FailureReason.WRONG_SIGNATURE,
                    agent_id,
                    proof_bytes=size,
                    submission_number=packet.submission_number,
                )

            try:
                encrypted = base64.b64decode(
                    packet.encrypted_fragment_response.encode("ascii"),
                    validate=True,
                )
                plaintext = SealedBox(self.private_key).decrypt(encrypted)
                response = FragmentResponse.model_validate_json(plaintext)
            except (ValueError, CryptoError, ValidationError):
                return fail(
                    FailureReason.DECRYPTION_FAILED,
                    agent_id,
                    proof_bytes=size,
                    submission_number=packet.submission_number,
                )

            if (
                response.agent_id != agent_id
                or response.message_id != message.message_id
                or response.challenge_id != challenge.challenge_id
                or response.fragment_commitment != registration.fragment_commitment
            ):
                return fail(
                    FailureReason.RESPONSE_BINDING_FAILED,
                    agent_id,
                    proof_bytes=size,
                    submission_number=packet.submission_number,
                )

            coords = response.coord_set()
            expected_commitment = proof_commitment(
                agent_id,
                message.message_id,
                challenge.challenge_id,
                coords,
            )
            if packet.proof_commitment != expected_commitment:
                return fail(
                    FailureReason.WRONG_PROOF_COMMITMENT,
                    agent_id,
                    proof_bytes=size,
                    submission_number=packet.submission_number,
                )

            expected = challenge.transform.apply(registration.fragment.coords)
            if coords != expected:
                return fail(
                    FailureReason.WRONG_GEOMETRY,
                    agent_id,
                    proof_bytes=size,
                    submission_number=packet.submission_number,
                )

            self._seen.add(seen_key)
            submitted_coords[agent_id] = coords
            events.append(
                VerificationEvent(
                    event_type="proof_verified",
                    agent_id=agent_id,
                    message_id=message.message_id,
                    challenge_id=challenge.challenge_id,
                    epoch=message.epoch,
                    valid=True,
                    proof_bytes=size,
                    latency_ms=elapsed(),
                    submission_number=packet.submission_number,
                )
            )

        missing = [agent_id for agent_id in self.registry.original_agent_ids if agent_id not in submitted_coords]
        if missing:
            return fail(FailureReason.MISSING_PACKET, missing[0])

        if not assembles_exactly(submitted_coords, self.registry.original_fragments(), challenge.transform):
            return fail(FailureReason.ASSEMBLY_FAILED, None)

        latency = elapsed()
        events.append(
            VerificationEvent(
                event_type="message_released",
                agent_id=message.receiver_id,
                message_id=message.message_id,
                challenge_id=challenge.challenge_id,
                epoch=message.epoch,
                valid=True,
                proof_bytes=proof_bytes_total,
                latency_ms=latency,
                submission_number=None,
            )
        )
        return VerificationResult(
            passed=True,
            released_message=message.content,
            failure_reason=None,
            ejection=None,
            collapsed=False,
            latency_ms=latency,
            proof_bytes_total=proof_bytes_total,
            events=events,
        )
