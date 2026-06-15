"""Reference gate adapters for the eval kit: USAG and UCOG.

Each adapter maps the kit's `AttackerCapability` onto the gate's existing attack
construction, so the kit reuses already-tested attack code rather than
re-implementing it.
"""

from __future__ import annotations

import json

from spatial_swarm.attacks.fake_agent import RandomFakeAgent
from spatial_swarm.attacks.valid_signature_agent import (
    StolenFragmentOnlyAgent,
    ValidSignatureWrongGeometryAgent,
)
from spatial_swarm.core.gateway import Gateway
from spatial_swarm.evalkit.gate import AttackerCapability, RoundOutcome
from spatial_swarm.experiments.fair_baselines import (
    ScenarioSpec,
    SwarmContext,
    build_ucog_packets,
    ucog_verify,
)
from spatial_swarm.protocol.verifier import VerificationResult


def _agent_ids(agent_count: int) -> list[str]:
    return [f"agent_{i:03d}" for i in range(1, agent_count + 1)]


def _target_and_source(agent_count: int) -> tuple[str, str]:
    ids = _agent_ids(agent_count)
    target = ids[len(ids) // 2 - 1] if len(ids) >= 2 else ids[0]
    source = next(a for a in ids if a != target)
    return target, source


def _outcome_from_usag(result: VerificationResult, secret_leaked: bool = False) -> RoundOutcome:
    failure = next((e for e in result.events if e.event_type == "proof_failed"), None)
    return RoundOutcome(
        passed=result.passed,
        failure_reason=result.failure_reason,
        failure_stage=failure.failure_stage if failure else None,
        secret_leaked=secret_leaked,
    )


class USAGGate:
    """The full USAG pipeline (spatial instantiation) as a Gate."""

    name = "usag"

    def _swarm(self, agent_count: int, fragment_size: int, seed: int) -> Gateway:
        return Gateway.create_swarm(agent_count=agent_count, fragment_size=fragment_size, seed=seed)

    def honest_round(self, agent_count: int, fragment_size: int, seed: int) -> RoundOutcome:
        gateway = self._swarm(agent_count, fragment_size, seed)
        return _outcome_from_usag(gateway.send("agent_001", "agent_002", {"body": "honest"}))

    def attack_round(
        self, agent_count: int, fragment_size: int, seed: int, capability: AttackerCapability
    ) -> RoundOutcome:
        gateway = self._swarm(agent_count, fragment_size, seed)
        if capability.is_positive_control:
            # The attacker holds everything needed; the reconstructed proof is honest.
            result = gateway.send("agent_001", "agent_002", {"body": "control"})
            return _outcome_from_usag(result, secret_leaked=True)
        target, source = _target_and_source(agent_count)
        if capability.has_signing_authority and not capability.has_target_secret:
            provider = ValidSignatureWrongGeometryAgent(target, source).replace_agent_packets
        elif capability.has_target_secret and not capability.has_signing_authority:
            provider = StolenFragmentOnlyAgent(target).replace_agent_packets
        else:
            provider = RandomFakeAgent(target).replace_agent_packets
        result = gateway.send("agent_001", "agent_002", {"body": "attack"}, packet_provider=provider)
        return _outcome_from_usag(result)

    def artifact_text(self, agent_count: int, fragment_size: int, seed: int) -> str:
        gateway = self._swarm(agent_count, fragment_size, seed)
        message = gateway.freeze("agent_001", "agent_002", {"body": "a"}, nonce="a")
        challenge = gateway.challenge(message)
        packets = gateway.collect_honest_packets(message, challenge)
        snapshot = gateway.verifier_public_snapshot_after_setup()
        return json.dumps(
            {
                "packets": [p.as_dict() for p in packets],
                "agents": [
                    {"agent_id": r.agent_id, "fragment_commitment": r.fragment_commitment}
                    for r in snapshot.agents
                ],
            },
            default=str,
        )


class UCOGGate:
    """The non-geometric unanimous commitment-opening gate as a Gate."""

    name = "ucog"

    def honest_round(self, agent_count: int, fragment_size: int, seed: int) -> RoundOutcome:
        ctx = SwarmContext.build(agent_count, fragment_size, seed)
        passed, reason = ucog_verify(ctx, build_ucog_packets(ctx, ScenarioSpec(honest=True)))
        return RoundOutcome(passed, None if passed else reason, None if passed else reason)

    def attack_round(
        self, agent_count: int, fragment_size: int, seed: int, capability: AttackerCapability
    ) -> RoundOutcome:
        ctx = SwarmContext.build(agent_count, fragment_size, seed)
        if capability.is_positive_control:
            passed, reason = ucog_verify(ctx, build_ucog_packets(ctx, ScenarioSpec(honest=True)))
            return RoundOutcome(passed, None if passed else reason, None, secret_leaked=True)
        if capability.has_signing_authority and not capability.has_target_secret:
            spec = ScenarioSpec(target_has_secret=False)
        elif capability.has_target_secret and not capability.has_signing_authority:
            spec = ScenarioSpec(target_has_signing_key=False, target_has_secret=True)
        else:
            spec = ScenarioSpec(target_has_signing_key=False, target_has_secret=False)
        passed, reason = ucog_verify(ctx, build_ucog_packets(ctx, spec))
        return RoundOutcome(passed, None if passed else reason, None if passed else reason)

    def artifact_text(self, agent_count: int, fragment_size: int, seed: int) -> str:
        ctx = SwarmContext.build(agent_count, fragment_size, seed)
        return json.dumps(build_ucog_packets(ctx, ScenarioSpec(honest=True)), default=str)
