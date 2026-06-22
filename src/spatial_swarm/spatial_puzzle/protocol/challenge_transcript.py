"""Per-agent challenge transcript for split-view coordinator tests."""

from __future__ import annotations

from dataclasses import dataclass, replace

from spatial_swarm.crypto.hashing import sha256_hex
from spatial_swarm.spatial_puzzle.protocol.challenge_envelope import ChallengeEnvelope


@dataclass(frozen=True)
class ChallengeView:
    agent_id: str
    challenge_digest: str
    nonce: str
    action_hash: str
    required_agent_set_digest: str
    allowed_effects_digest: str
    transaction_digest: str
    role_map_digest: str
    path_commitment_digest: str
    endpoint_commitment_digest: str
    timestamp: int

    @staticmethod
    def from_challenge(agent_id: str, challenge: ChallengeEnvelope) -> "ChallengeView":
        return ChallengeView(
            agent_id=agent_id,
            challenge_digest=challenge.wrapper_challenge_digest,
            nonce=challenge.nonce,
            action_hash=challenge.action_hash,
            required_agent_set_digest=sha256_hex(
                {
                    "kind": "challenge_view_required_agent_set_v1",
                    "required_agent_set": list(challenge.required_agent_set),
                }
            ),
            allowed_effects_digest=challenge.allowed_effects_digest,
            transaction_digest=challenge.transaction_digest,
            role_map_digest=challenge.role_map_digest,
            path_commitment_digest=challenge.path_commitment_digest,
            endpoint_commitment_digest=challenge.endpoint_commitment_digest,
            timestamp=challenge.issued_at,
        )

    def canonical(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "challenge_digest": self.challenge_digest,
            "nonce": self.nonce,
            "action_hash": self.action_hash,
            "required_agent_set_digest": self.required_agent_set_digest,
            "allowed_effects_digest": self.allowed_effects_digest,
            "transaction_digest": self.transaction_digest,
            "role_map_digest": self.role_map_digest,
            "path_commitment_digest": self.path_commitment_digest,
            "endpoint_commitment_digest": self.endpoint_commitment_digest,
            "timestamp": self.timestamp,
        }


@dataclass(frozen=True)
class ChallengeTranscript:
    views: tuple[ChallengeView, ...]

    @staticmethod
    def from_challenge(challenge: ChallengeEnvelope) -> "ChallengeTranscript":
        return ChallengeTranscript(
            tuple(ChallengeView.from_challenge(agent, challenge) for agent in challenge.required_agent_set)
        )

    def with_split(self, field: str, value: str, *, agent_index: int = -1) -> "ChallengeTranscript":
        views = list(self.views)
        index = agent_index % len(views)
        views[index] = replace(views[index], **{field: value})
        return ChallengeTranscript(tuple(views))

    def consistency_reasons(self, challenge: ChallengeEnvelope) -> tuple[str, ...]:
        reasons: list[str] = []
        required = set(challenge.required_agent_set)
        seen = [view.agent_id for view in self.views]
        if set(seen) != required or len(seen) != len(set(seen)):
            reasons.append("challenge:multi_view_inconsistency")
        for field in (
            "challenge_digest",
            "nonce",
            "action_hash",
            "required_agent_set_digest",
            "allowed_effects_digest",
            "transaction_digest",
            "role_map_digest",
            "path_commitment_digest",
            "endpoint_commitment_digest",
        ):
            values = {getattr(view, field) for view in self.views}
            if len(values) > 1:
                reasons.append("challenge:multi_view_inconsistency")
        expected = ChallengeView.from_challenge(challenge.required_agent_set[0], challenge)
        expected_by_field = expected.canonical()
        for view in self.views:
            row = view.canonical()
            for field in (
                "challenge_digest",
                "nonce",
                "action_hash",
                "required_agent_set_digest",
                "allowed_effects_digest",
                "transaction_digest",
                "role_map_digest",
                "path_commitment_digest",
                "endpoint_commitment_digest",
            ):
                if row[field] != expected_by_field[field]:
                    reasons.append("challenge:multi_view_inconsistency")
                    break
        return tuple(sorted(set(reasons)))

    def canonical(self) -> list[dict]:
        return [view.canonical() for view in self.views]
