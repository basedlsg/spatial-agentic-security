"""ChallengeBuilder tests."""

import tempfile
from pathlib import Path

from spatial_swarm.spatial_puzzle.experiments import real_sandbox_gate_v3 as V3
from spatial_swarm.spatial_puzzle.protocol import ChallengeBuilder
from spatial_swarm.spatial_puzzle.sandbox import ContainerAdapter


def _env(action_type: str = "credential_read"):
    raw = V3._default_raw(action_type)
    guard = V3.GuardConfig(min_block_ms=0)
    with tempfile.TemporaryDirectory() as tmp:
        repo = ContainerAdapter(guard.spec_for(raw)).create_repo_template(Path(tmp))
        return V3.ActionCanonicalizerV3(repo, guard=guard, raw=raw).envelope(nonce_label="builder-test")


def test_challenge_builder_binds_wrapper_truth():
    env = _env()
    challenge = ChallengeBuilder(0).build(env, transaction_digest="tx")
    assert challenge.self_consistent()
    assert challenge.action_hash == env.action_hash
    assert challenge.risk_level == env.risk_level
    assert challenge.required_agent_set == env.required_agents
    assert challenge.required_agent_count == len(env.required_agents)
    assert challenge.allowed_effects_digest == env.expected_effect_digest
    assert challenge.transaction_digest == "tx"
