"""Wrapper-side challenge builder."""

from __future__ import annotations

from dataclasses import dataclass

from spatial_swarm.crypto.hashing import sha256_hex
from spatial_swarm.spatial_puzzle.experiments import formation_gate as FG
from spatial_swarm.spatial_puzzle.experiments import real_sandbox_gate_v3 as V3
from spatial_swarm.spatial_puzzle.protocol.challenge_envelope import ChallengeEnvelope


NO_TRANSACTION_DIGEST = "no_transaction"


@dataclass(frozen=True)
class ChallengeBuilder:
    trial_index: int
    formation_family: str = "coordinated_formation"
    coordinator_id: str = "coordinator_001"
    issued_at: int = 1_700_000_000
    ttl_seconds: int = 300

    def build(
        self,
        env: V3.ActionEnvelopeV3,
        *,
        transaction_digest: str = NO_TRANSACTION_DIGEST,
        action_hash: str | None = None,
        canonical_action_digest: str | None = None,
        risk_level: str | None = None,
        required_agent_set: tuple[str, ...] | None = None,
        required_agent_count: int | None = None,
        allowed_effects_digest: str | None = None,
        nonce: str | None = None,
        issued_at: int | None = None,
        expires_at: int | None = None,
        coordinator_id: str | None = None,
    ) -> ChallengeEnvelope:
        submitted_action_hash = action_hash or env.action_hash
        submitted_risk = risk_level or env.risk_level
        submitted_required = tuple(required_agent_set or env.required_agents)
        submitted_nonce = nonce or self._fresh_nonce(
            submitted_action_hash,
            submitted_risk,
            submitted_required,
            transaction_digest,
        )
        path_digest, endpoint_digest = self._commitment_digests(
            submitted_action_hash,
            submitted_nonce,
            submitted_risk,
            submitted_required,
        )
        issued = self.issued_at if issued_at is None else issued_at
        expires = issued + self.ttl_seconds if expires_at is None else expires_at
        return ChallengeEnvelope.create(
            action_hash=submitted_action_hash,
            canonical_action_digest=canonical_action_digest or self.canonical_action_digest(env),
            risk_level=submitted_risk,
            required_agent_set=submitted_required,
            required_agent_count=required_agent_count,
            allowed_effects_digest=allowed_effects_digest or env.expected_effect_digest,
            transaction_digest=transaction_digest,
            nonce=submitted_nonce,
            formation_family=self.formation_family,
            path_commitment_digest=path_digest,
            endpoint_commitment_digest=endpoint_digest,
            role_map_digest=self.role_map_digest(submitted_required),
            issued_at=issued,
            expires_at=expires,
            coordinator_id=self.coordinator_id if coordinator_id is None else coordinator_id,
        )

    def canonical_action_digest(self, env: V3.ActionEnvelopeV3) -> str:
        return sha256_hex(
            {
                "kind": "coordinator_challenge_canonical_action_v1",
                "action": env.canonical(),
            }
        )

    def role_map_digest(self, required_agent_set: tuple[str, ...]) -> str:
        arm = FG.FormationArm(self.formation_family, FG.FormationConfig(), self.trial_index)
        return sha256_hex(
            {
                "kind": "coordinator_challenge_role_map_v1",
                "roles": [
                    {"agent_id": agent, "role": arm.roles.get(agent, "unknown")}
                    for agent in required_agent_set
                ],
            }
        )

    def _fresh_nonce(
        self,
        action_hash: str,
        risk_level: str,
        required_agent_set: tuple[str, ...],
        transaction_digest: str,
    ) -> str:
        arm = FG.FormationArm(self.formation_family, FG.FormationConfig(), self.trial_index)
        for counter in range(512):
            nonce = sha256_hex(
                {
                    "kind": "coordinator_challenge_nonce_v1",
                    "trial_index": self.trial_index,
                    "formation_family": self.formation_family,
                    "action_hash": action_hash,
                    "risk_level": risk_level,
                    "required_agent_set": list(required_agent_set),
                    "transaction_digest": transaction_digest,
                    "counter": counter,
                }
            )[:32]
            challenge = FG.FormationChallenge(
                arm=self.formation_family,
                action_hash=action_hash,
                nonce=nonce,
                risk=risk_level,
                required_agents=required_agent_set,
            )
            try:
                ok, _ = arm.formation_valid(challenge)
            except (IndexError, ValueError):
                ok = False
            if ok:
                return nonce
        return sha256_hex(
            {
                "kind": "coordinator_challenge_fallback_nonce_v1",
                "trial_index": self.trial_index,
                "action_hash": action_hash,
                "required_agent_set": list(required_agent_set),
            }
        )[:32]

    def _commitment_digests(
        self,
        action_hash: str,
        nonce: str,
        risk_level: str,
        required_agent_set: tuple[str, ...],
    ) -> tuple[str, str]:
        arm = FG.FormationArm(self.formation_family, FG.FormationConfig(), self.trial_index)
        challenge = FG.FormationChallenge(
            arm=self.formation_family,
            action_hash=action_hash,
            nonce=nonce,
            risk=risk_level,
            required_agents=required_agent_set,
        )
        traces = {agent: arm.expected_trace(agent, challenge) for agent in required_agent_set}
        return (
            sha256_hex(
                {
                    "kind": "coordinator_challenge_path_commitment_v1",
                    "paths": {agent: traces[agent].path_digest for agent in required_agent_set},
                }
            ),
            sha256_hex(
                {
                    "kind": "coordinator_challenge_endpoint_commitment_v1",
                    "endpoints": {agent: traces[agent].endpoint_digest for agent in required_agent_set},
                }
            ),
        )
