"""Dishonest coordinator model for challenge hardening experiments."""

from __future__ import annotations

from dataclasses import dataclass

from spatial_swarm.crypto.hashing import sha256_hex
from spatial_swarm.spatial_puzzle.experiments import real_sandbox_gate_v3 as V3
from spatial_swarm.spatial_puzzle.protocol.challenge_builder import ChallengeBuilder, NO_TRANSACTION_DIGEST
from spatial_swarm.spatial_puzzle.protocol.challenge_envelope import ChallengeEnvelope
from spatial_swarm.spatial_puzzle.protocol.challenge_transcript import ChallengeTranscript


@dataclass(frozen=True)
class CoordinatorModel:
    builder: ChallengeBuilder

    def honest(
        self,
        env: V3.ActionEnvelopeV3,
        *,
        transaction_digest: str = NO_TRANSACTION_DIGEST,
    ) -> tuple[ChallengeEnvelope, ChallengeTranscript]:
        challenge = self.builder.build(env, transaction_digest=transaction_digest)
        return challenge, ChallengeTranscript.from_challenge(challenge)

    def risk_downgrade(
        self,
        env: V3.ActionEnvelopeV3,
        *,
        risk_level: str = "low",
        transaction_digest: str = NO_TRANSACTION_DIGEST,
    ) -> tuple[ChallengeEnvelope, ChallengeTranscript]:
        challenge = self.builder.build(
            env,
            risk_level=risk_level,
            transaction_digest=transaction_digest,
        )
        return challenge, ChallengeTranscript.from_challenge(challenge)

    def fewer_agents(
        self,
        env: V3.ActionEnvelopeV3,
        *,
        count: int = 2,
        transaction_digest: str = NO_TRANSACTION_DIGEST,
    ) -> tuple[ChallengeEnvelope, ChallengeTranscript]:
        required = tuple(env.required_agents[:count])
        challenge = self.builder.build(
            env,
            required_agent_set=required,
            required_agent_count=len(required),
            transaction_digest=transaction_digest,
        )
        return challenge, ChallengeTranscript.from_challenge(challenge)

    def wrong_agent_identities(
        self,
        env: V3.ActionEnvelopeV3,
        *,
        variant: str,
        transaction_digest: str = NO_TRANSACTION_DIGEST,
    ) -> tuple[ChallengeEnvelope, ChallengeTranscript]:
        agents = list(env.required_agents)
        if variant == "swap_trusted_for_fake":
            agents[-1] = "agent_999"
        elif variant == "duplicate_agent":
            agents[-1] = agents[0]
        elif variant == "swap_trusted_for_known":
            agents[-1] = "agent_004" if agents[-1] != "agent_004" else "agent_003"
        elif variant == "missing_one":
            agents = agents[:-1]
        else:
            raise ValueError(variant)
        challenge = self.builder.build(
            env,
            required_agent_set=tuple(agents),
            required_agent_count=len(agents),
            transaction_digest=transaction_digest,
        )
        return challenge, ChallengeTranscript.from_challenge(challenge)

    def allowed_effects_expansion(
        self,
        env: V3.ActionEnvelopeV3,
        *,
        label: str,
        transaction_digest: str = NO_TRANSACTION_DIGEST,
    ) -> tuple[ChallengeEnvelope, ChallengeTranscript]:
        expanded = sha256_hex(
            {
                "kind": "dishonest_allowed_effects_expansion_v1",
                "label": label,
                "original": env.expected_effect_digest,
            }
        )
        challenge = self.builder.build(
            env,
            allowed_effects_digest=expanded,
            transaction_digest=transaction_digest,
        )
        return challenge, ChallengeTranscript.from_challenge(challenge)

    def action_substitution(
        self,
        env: V3.ActionEnvelopeV3,
        *,
        old_env: V3.ActionEnvelopeV3,
        transaction_digest: str = NO_TRANSACTION_DIGEST,
    ) -> tuple[ChallengeEnvelope, ChallengeTranscript]:
        challenge = self.builder.build(
            env,
            action_hash=old_env.action_hash,
            canonical_action_digest=self.builder.canonical_action_digest(old_env),
            transaction_digest=transaction_digest,
        )
        return challenge, ChallengeTranscript.from_challenge(challenge)

    def transaction_substitution(
        self,
        env: V3.ActionEnvelopeV3,
        *,
        false_transaction_digest: str,
    ) -> tuple[ChallengeEnvelope, ChallengeTranscript]:
        challenge = self.builder.build(env, transaction_digest=false_transaction_digest)
        return challenge, ChallengeTranscript.from_challenge(challenge)

    def split_view(
        self,
        env: V3.ActionEnvelopeV3,
        *,
        field: str,
        transaction_digest: str = NO_TRANSACTION_DIGEST,
    ) -> tuple[ChallengeEnvelope, ChallengeTranscript]:
        challenge = self.builder.build(env, transaction_digest=transaction_digest)
        mutated = sha256_hex(
            {
                "kind": "dishonest_split_view_v1",
                "field": field,
                "challenge": challenge.wrapper_challenge_digest,
            }
        )
        return challenge, ChallengeTranscript.from_challenge(challenge).with_split(field, mutated)

    def stale(
        self,
        env: V3.ActionEnvelopeV3,
        *,
        transaction_digest: str = NO_TRANSACTION_DIGEST,
        issued_at: int,
        expires_at: int,
    ) -> tuple[ChallengeEnvelope, ChallengeTranscript]:
        challenge = self.builder.build(
            env,
            transaction_digest=transaction_digest,
            issued_at=issued_at,
            expires_at=expires_at,
        )
        return challenge, ChallengeTranscript.from_challenge(challenge)

    def coordinator_identity(
        self,
        env: V3.ActionEnvelopeV3,
        *,
        coordinator_id: str,
        transaction_digest: str = NO_TRANSACTION_DIGEST,
    ) -> tuple[ChallengeEnvelope, ChallengeTranscript]:
        challenge = self.builder.build(
            env,
            coordinator_id=coordinator_id,
            transaction_digest=transaction_digest,
        )
        return challenge, ChallengeTranscript.from_challenge(challenge)
