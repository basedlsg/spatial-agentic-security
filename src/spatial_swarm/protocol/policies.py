"""Proof envelope and strict one-shot policies."""

from __future__ import annotations

import math
from dataclasses import dataclass

from spatial_swarm.crypto.hashing import canonical_json


@dataclass(frozen=True)
class ProofEnvelope:
    min_bytes: int
    max_bytes: int
    timeout_ms: float
    max_submissions: int = 1

    def validate_size(self, size_bytes: int) -> str:
        if size_bytes < self.min_bytes:
            return "under"
        if size_bytes > self.max_bytes:
            return "over"
        return "ok"


def _base64_len(raw_len: int) -> int:
    return 4 * math.ceil(raw_len / 3)


def estimate_envelope(
    agent_id: str,
    epoch: str,
    fragment_size: int,
    p: int,
    timeout_ms: float,
) -> ProofEnvelope:
    """Estimate a fragment-specific proof packet envelope.

    The response is sealed with PyNaCl SealedBox, which adds 48 bytes and then base64
    expansion. The range accounts for different coordinate digit lengths.
    """

    min_coord = [[0, 0, 0] for _ in range(fragment_size)]
    max_coord = [[p - 1, p - 1, p - 1] for _ in range(fragment_size)]

    def packet_len(coords: list[list[int]]) -> int:
        response = {
            "agent_id": agent_id,
            "challenge_id": "0" * 64,
            "coords": coords,
            "fragment_commitment": "0" * 64,
            "message_id": "0" * 64,
        }
        encrypted_len = _base64_len(len(canonical_json(response).encode("utf-8")) + 48)
        packet = {
            "agent_id": agent_id,
            "challenge_id": "0" * 64,
            "encrypted_fragment_response": "x" * encrypted_len,
            "epoch": epoch,
            "message_id": "0" * 64,
            "proof_commitment": "0" * 64,
            "proof_version": "v1",
            "signature": "x" * 88,
            "submission_number": 1,
            "submitted_at_ms": 0.0,
        }
        return len(canonical_json(packet).encode("utf-8"))

    lower = packet_len(min_coord)
    upper = packet_len(max_coord)
    margin = 96
    return ProofEnvelope(
        min_bytes=max(0, lower - margin),
        max_bytes=upper + margin,
        timeout_ms=timeout_ms,
        max_submissions=1,
    )
