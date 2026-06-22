"""ChallengeEnvelope tests."""

from spatial_swarm.spatial_puzzle.protocol import ChallengeEnvelope


def test_challenge_envelope_recomputes_digest_after_updates():
    challenge = ChallengeEnvelope.create(
        action_hash="a",
        canonical_action_digest="c",
        risk_level="high",
        required_agent_set=("agent_001", "agent_002"),
        allowed_effects_digest="e",
        transaction_digest="tx",
        nonce="n",
        formation_family="coordinated_formation",
        path_commitment_digest="p",
        endpoint_commitment_digest="ep",
        role_map_digest="r",
        issued_at=10,
        expires_at=20,
        coordinator_id="coordinator_001",
    )
    assert challenge.self_consistent()
    changed = challenge.with_updates(risk_level="low")
    assert changed.self_consistent()
    assert changed.wrapper_challenge_digest != challenge.wrapper_challenge_digest
    assert changed.challenge_id == changed.wrapper_challenge_digest[:16]
