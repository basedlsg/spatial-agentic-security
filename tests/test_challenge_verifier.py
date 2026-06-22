"""ChallengeVerifier tests."""

import tempfile
from dataclasses import replace
from pathlib import Path

from spatial_swarm.spatial_puzzle.experiments import real_sandbox_gate_v3 as V3
from spatial_swarm.spatial_puzzle.protocol import (
    ChallengeBuilder,
    ChallengeTranscript,
    ChallengeVerifier,
    ChallengeVerifierConfig,
    CoordinatorModel,
)
from spatial_swarm.spatial_puzzle.sandbox import ContainerAdapter


def _env(action_type: str = "credential_read"):
    raw = V3._default_raw(action_type)
    guard = V3.GuardConfig(min_block_ms=0)
    with tempfile.TemporaryDirectory() as tmp:
        repo = ContainerAdapter(guard.spec_for(raw)).create_repo_template(Path(tmp))
        return V3.ActionCanonicalizerV3(repo, guard=guard, raw=raw).envelope(nonce_label="verifier-test")


def test_verifier_accepts_honest_challenge():
    env = _env()
    builder = ChallengeBuilder(0)
    challenge, transcript = CoordinatorModel(builder).honest(env)
    result = ChallengeVerifier().verify(challenge, env=env, builder=builder, transcript=transcript)
    assert result.verified is True
    assert result.internal_reasons == ()


def test_verifier_blocks_risk_downgrade_before_geometry():
    env = _env()
    builder = ChallengeBuilder(1)
    challenge, transcript = CoordinatorModel(builder).risk_downgrade(env, risk_level="low")
    result = ChallengeVerifier().verify(challenge, env=env, builder=builder, transcript=transcript)
    assert result.verified is False
    assert "challenge:risk_mismatch" in result.internal_reasons
    ablated = ChallengeVerifier(
        replace(ChallengeVerifierConfig(), risk_recompute=False)
    ).verify(challenge, env=env, builder=builder, transcript=transcript)
    assert ablated.verified is True


def test_verifier_blocks_fresh_fewer_agent_challenge_and_ablation_releases():
    env = _env()
    builder = ChallengeBuilder(2)
    challenge, transcript = CoordinatorModel(builder).fewer_agents(env, count=2)
    result = ChallengeVerifier().verify(challenge, env=env, builder=builder, transcript=transcript)
    assert result.verified is False
    assert "challenge:required_agent_set_mismatch" in result.internal_reasons
    ablated = ChallengeVerifier(
        replace(ChallengeVerifierConfig(), required_agent_recompute=False)
    ).verify(challenge, env=env, builder=builder, transcript=transcript)
    assert ablated.verified is True


def test_verifier_blocks_split_view_and_ablation_releases():
    env = _env("run_tests")
    builder = ChallengeBuilder(3)
    challenge, transcript = CoordinatorModel(builder).split_view(env, field="action_hash")
    result = ChallengeVerifier().verify(challenge, env=env, builder=builder, transcript=transcript)
    assert result.verified is False
    assert "challenge:multi_view_inconsistency" in result.internal_reasons
    ablated = ChallengeVerifier(
        replace(ChallengeVerifierConfig(), multi_view_consistency=False)
    ).verify(challenge, env=env, builder=builder, transcript=transcript)
    assert ablated.verified is True


def test_verifier_blocks_nonce_reuse_and_expiry():
    env = _env("read_file")
    builder = ChallengeBuilder(4)
    challenge, transcript = CoordinatorModel(builder).honest(env)
    reused = ChallengeVerifier(
        replace(ChallengeVerifierConfig(), used_nonces=frozenset({challenge.nonce}))
    ).verify(challenge, env=env, builder=builder, transcript=transcript)
    assert reused.verified is False
    assert "challenge:nonce_reuse" in reused.internal_reasons

    expired, expired_transcript = CoordinatorModel(builder).stale(
        env,
        issued_at=1_699_999_000,
        expires_at=1_699_999_100,
    )
    result = ChallengeVerifier().verify(
        expired,
        env=env,
        builder=builder,
        transcript=expired_transcript,
    )
    assert result.verified is False
    assert "challenge:expired" in result.internal_reasons


def test_verifier_detects_transcript_digest_not_self_consistent():
    env = _env("run_command")
    builder = ChallengeBuilder(5)
    challenge, transcript = CoordinatorModel(builder).honest(env)
    broken = ChallengeTranscript(tuple(transcript.views[:-1]))
    result = ChallengeVerifier().verify(challenge, env=env, builder=builder, transcript=broken)
    assert result.verified is False
    assert "challenge:multi_view_inconsistency" in result.internal_reasons
