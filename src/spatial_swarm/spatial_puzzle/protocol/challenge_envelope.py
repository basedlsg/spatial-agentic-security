"""Strict challenge envelope for coordinator hardening experiments."""

from __future__ import annotations

from dataclasses import dataclass, replace

from spatial_swarm.crypto.hashing import sha256_hex


@dataclass(frozen=True)
class ChallengeEnvelope:
    challenge_id: str
    action_hash: str
    canonical_action_digest: str
    risk_level: str
    required_agent_set: tuple[str, ...]
    required_agent_count: int
    allowed_effects_digest: str
    transaction_digest: str
    nonce: str
    formation_family: str
    path_commitment_digest: str
    endpoint_commitment_digest: str
    role_map_digest: str
    issued_at: int
    expires_at: int
    coordinator_id: str
    wrapper_challenge_digest: str

    @staticmethod
    def create(
        *,
        action_hash: str,
        canonical_action_digest: str,
        risk_level: str,
        required_agent_set: tuple[str, ...],
        allowed_effects_digest: str,
        transaction_digest: str,
        nonce: str,
        formation_family: str,
        path_commitment_digest: str,
        endpoint_commitment_digest: str,
        role_map_digest: str,
        issued_at: int,
        expires_at: int,
        coordinator_id: str,
        required_agent_count: int | None = None,
    ) -> "ChallengeEnvelope":
        base = ChallengeEnvelope(
            challenge_id="",
            action_hash=action_hash,
            canonical_action_digest=canonical_action_digest,
            risk_level=risk_level,
            required_agent_set=tuple(required_agent_set),
            required_agent_count=(
                len(required_agent_set) if required_agent_count is None else required_agent_count
            ),
            allowed_effects_digest=allowed_effects_digest,
            transaction_digest=transaction_digest,
            nonce=nonce,
            formation_family=formation_family,
            path_commitment_digest=path_commitment_digest,
            endpoint_commitment_digest=endpoint_commitment_digest,
            role_map_digest=role_map_digest,
            issued_at=issued_at,
            expires_at=expires_at,
            coordinator_id=coordinator_id,
            wrapper_challenge_digest="",
        )
        digest = base.compute_wrapper_digest()
        return replace(base, challenge_id=digest[:16], wrapper_challenge_digest=digest)

    def canonical(self, *, include_digests: bool = True) -> dict:
        body = {
            "action_hash": self.action_hash,
            "canonical_action_digest": self.canonical_action_digest,
            "risk_level": self.risk_level,
            "required_agent_set": list(self.required_agent_set),
            "required_agent_count": self.required_agent_count,
            "allowed_effects_digest": self.allowed_effects_digest,
            "transaction_digest": self.transaction_digest,
            "nonce": self.nonce,
            "formation_family": self.formation_family,
            "path_commitment_digest": self.path_commitment_digest,
            "endpoint_commitment_digest": self.endpoint_commitment_digest,
            "role_map_digest": self.role_map_digest,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "coordinator_id": self.coordinator_id,
        }
        if include_digests:
            body["challenge_id"] = self.challenge_id
            body["wrapper_challenge_digest"] = self.wrapper_challenge_digest
        return body

    def compute_wrapper_digest(self) -> str:
        return sha256_hex(
            {
                "kind": "coordinator_challenge_envelope_v1",
                "challenge": self.canonical(include_digests=False),
            }
        )

    def self_consistent(self) -> bool:
        digest = self.compute_wrapper_digest()
        return self.wrapper_challenge_digest == digest and self.challenge_id == digest[:16]

    def with_updates(self, **updates) -> "ChallengeEnvelope":
        body = self.canonical(include_digests=False)
        body.update(updates)
        if "required_agent_set" in body:
            body["required_agent_set"] = tuple(body["required_agent_set"])
        return ChallengeEnvelope.create(**body)
