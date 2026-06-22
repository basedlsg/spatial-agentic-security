"""Challenge verifier that treats the wrapper as source of truth."""

from __future__ import annotations

from dataclasses import dataclass, field

from spatial_swarm.spatial_puzzle.experiments import real_sandbox_gate_v3 as V3
from spatial_swarm.spatial_puzzle.protocol.challenge_builder import ChallengeBuilder, NO_TRANSACTION_DIGEST
from spatial_swarm.spatial_puzzle.protocol.challenge_envelope import ChallengeEnvelope
from spatial_swarm.spatial_puzzle.protocol.challenge_transcript import ChallengeTranscript


@dataclass(frozen=True)
class ChallengeVerifierConfig:
    wrapper_recompute: bool = True
    risk_recompute: bool = True
    required_agent_recompute: bool = True
    required_agent_identity_binding: bool = True
    action_hash_binding: bool = True
    allowed_effects_digest_binding: bool = True
    transaction_digest_binding: bool = True
    nonce_freshness: bool = True
    challenge_expiry: bool = True
    multi_view_consistency: bool = True
    geometry_after_challenge: bool = True
    coordinator_identity_check: bool = True
    allowed_coordinators: tuple[str, ...] = ("coordinator_001",)
    now: int = 1_700_000_010
    used_nonces: frozenset[str] = field(default_factory=frozenset)


@dataclass(frozen=True)
class ChallengeVerificationResult:
    verified: bool
    internal_reasons: tuple[str, ...]
    expected_challenge: ChallengeEnvelope | None = None


class ChallengeVerifier:
    def __init__(self, config: ChallengeVerifierConfig = ChallengeVerifierConfig()) -> None:
        self.config = config

    def verify(
        self,
        submitted: ChallengeEnvelope,
        *,
        env: V3.ActionEnvelopeV3,
        builder: ChallengeBuilder,
        transcript: ChallengeTranscript,
        transaction_digest: str = NO_TRANSACTION_DIGEST,
    ) -> ChallengeVerificationResult:
        reasons: list[str] = []
        if not submitted.self_consistent():
            reasons.append("challenge:wrapper_digest_invalid")
        if self.config.coordinator_identity_check:
            if not submitted.coordinator_id:
                reasons.append("challenge:coordinator_missing")
            elif submitted.coordinator_id not in self.config.allowed_coordinators:
                reasons.append("challenge:unknown_coordinator")
        if self.config.challenge_expiry and submitted.expires_at < self.config.now:
            reasons.append("challenge:expired")
        if self.config.nonce_freshness and submitted.nonce in self.config.used_nonces:
            reasons.append("challenge:nonce_reuse")

        expected: ChallengeEnvelope | None = None
        if self.config.wrapper_recompute:
            expected = builder.build(
                env,
                transaction_digest=transaction_digest,
                issued_at=submitted.issued_at,
                expires_at=submitted.expires_at,
                coordinator_id=submitted.coordinator_id,
            )
            if self.config.action_hash_binding:
                if submitted.action_hash != expected.action_hash:
                    reasons.append("challenge:action_hash_mismatch")
                if submitted.canonical_action_digest != expected.canonical_action_digest:
                    reasons.append("challenge:action_hash_mismatch")
            if self.config.risk_recompute and submitted.risk_level != expected.risk_level:
                reasons.append("challenge:risk_mismatch")
            if self.config.required_agent_recompute:
                if submitted.required_agent_count != expected.required_agent_count:
                    reasons.append("challenge:required_agent_set_mismatch")
            if self.config.required_agent_identity_binding:
                submitted_set = set(submitted.required_agent_set)
                if len(submitted.required_agent_set) != len(submitted_set):
                    reasons.append("challenge:required_agent_set_mismatch")
                if submitted.required_agent_count == expected.required_agent_count:
                    if submitted_set != set(expected.required_agent_set):
                        reasons.append("challenge:required_agent_set_mismatch")
                    if submitted.role_map_digest != expected.role_map_digest:
                        reasons.append("challenge:required_agent_set_mismatch")
            if (
                self.config.allowed_effects_digest_binding
                and submitted.allowed_effects_digest != expected.allowed_effects_digest
            ):
                reasons.append("challenge:allowed_effects_digest_mismatch")
            if (
                self.config.transaction_digest_binding
                and submitted.transaction_digest != expected.transaction_digest
            ):
                reasons.append("challenge:transaction_digest_mismatch")

        if self.config.multi_view_consistency:
            reasons.extend(transcript.consistency_reasons(submitted))

        clean = tuple(sorted(set(reasons)))
        return ChallengeVerificationResult(
            verified=not clean,
            internal_reasons=clean,
            expected_challenge=expected,
        )
