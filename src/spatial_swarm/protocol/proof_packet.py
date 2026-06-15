"""Proof packet schemas."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from spatial_swarm.crypto.hashing import canonical_json


class FragmentResponse(BaseModel):
    agent_id: str
    message_id: str
    challenge_id: str
    fragment_commitment: str
    coords: list[list[int]]

    def coord_set(self) -> set[tuple[int, int, int]]:
        return {(int(x), int(y), int(z)) for x, y, z in self.coords}


class ProofPacket(BaseModel):
    agent_id: str
    swarm_id: str
    epoch: str
    message_id: str
    challenge_id: str
    proof_version: str = "v1"
    submission_number: int = Field(ge=1)
    proof_commitment: str
    encrypted_fragment_response: str
    signature: str
    submitted_at_ms: float = 0.0

    def as_dict(self) -> dict[str, Any]:
        return self.model_dump()

    def signed_payload(self) -> dict[str, Any]:
        payload = self.as_dict()
        payload.pop("signature", None)
        return payload


def packet_size_bytes(packet: ProofPacket) -> int:
    return len(canonical_json(packet.as_dict()).encode("utf-8"))


def unsigned_packet_payload(packet_fields: dict[str, Any]) -> dict[str, Any]:
    payload = dict(packet_fields)
    payload.pop("signature", None)
    return payload
