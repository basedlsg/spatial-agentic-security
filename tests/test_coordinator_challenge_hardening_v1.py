"""Coordinator / Challenge Hardening v1 tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from spatial_swarm.spatial_puzzle.experiments import coordinator_challenge_hardening_v1 as CCH

from _env_guards import needs_docker


def test_fresh_smaller_challenge_blocks_and_required_agent_ablation_releases():
    guard = CCH.ChallengeGateGuard(min_block_ms=0)
    full, _ = CCH.run_fewer_agent_challenge("credential_read_fresh_2_agents", 0, guard)
    assert full.blocked is True
    assert full.blocked_before_geometry is True
    assert "challenge:required_agent_set_mismatch" in full.internal_reasons

    ablated, _ = CCH.run_ablation_case("no_required_agent_recompute", 0, guard)
    assert ablated.released is True
    assert ablated.challenge_verified is True
    assert ablated.formation_released is True

    identity, _ = CCH.run_fewer_agent_challenge("correct_count_wrong_identities", 0, guard)
    assert identity.blocked_before_geometry is True
    no_identity, _ = CCH.run_ablation_case("no_required_agent_identity_binding", 0, guard)
    assert no_identity.released is True


def test_risk_downgrade_blocks_before_geometry_and_ablation_releases():
    guard = CCH.ChallengeGateGuard(min_block_ms=0)
    full, _ = CCH.run_risk_downgrade("credential_read_marked_low_risk", 0, guard)
    assert full.blocked_before_geometry is True
    assert "challenge:risk_mismatch" in full.internal_reasons

    ablated, _ = CCH.run_ablation_case("no_risk_recompute", 0, guard)
    assert ablated.released is True


def test_allowed_effect_and_action_hash_bindings_have_distinct_jobs():
    guard = CCH.ChallengeGateGuard(min_block_ms=0)
    effect, _ = CCH.run_allowed_effects_expansion("read_file_challenge_allows_write", 0, guard)
    assert effect.blocked_before_geometry is True
    assert "challenge:allowed_effects_digest_mismatch" in effect.internal_reasons
    no_effect_digest, _ = CCH.run_ablation_case("no_allowed_effects_digest_binding", 0, guard)
    assert no_effect_digest.released is True

    substitution, _ = CCH.run_action_substitution("same_action_type_different_path", 0, guard)
    assert substitution.blocked_before_geometry is True
    assert "challenge:action_hash_mismatch" in substitution.internal_reasons
    no_action_hash, _ = CCH.run_ablation_case("no_action_hash_binding", 0, guard)
    assert no_action_hash.released is True


def test_split_view_and_geometry_bypass_ablations():
    guard = CCH.ChallengeGateGuard(min_block_ms=0)
    split, _ = CCH.run_multi_view_challenge("split_action_hash_across_agents", 0, guard)
    assert split.blocked_before_geometry is True
    assert "challenge:multi_view_inconsistency" in split.internal_reasons
    no_consistency, _ = CCH.run_ablation_case("no_multi_view_consistency", 0, guard)
    assert no_consistency.released is True

    full_geometry, _ = CCH.attempt_challenge_action(
        CCH.V3._default_raw("credential_read"),
        suite="test",
        scenario="fake_proof",
        trial_index=0,
        guard=guard,
        geometry_attack="fake_proof",
    )
    assert full_geometry.blocked_at_geometry is True
    no_geometry, _ = CCH.run_ablation_case("no_geometry_after_challenge", 0, guard)
    assert no_geometry.released is True


@needs_docker
def test_tiny_cli_run_writes_required_artifacts(tmp_path: Path):
    run_dir = CCH.main(
        [
            "--mode",
            "smoke",
            "--valid-trials",
            "0",
            "--attack-trials",
            "0",
            "--ablation-trials",
            "0",
            "--transaction-trials",
            "0",
            "--multi-view-trials",
            "0",
            "--replay-trials",
            "0",
            "--constant-failure-trials",
            "0",
            "--min-block-ms",
            "0",
            "--output-root",
            str(tmp_path),
        ]
    )
    digest = (run_dir / "metrics.json.sha256").read_text(encoding="utf-8").strip()
    assert digest == hashlib.sha256((run_dir / "metrics.json").read_bytes()).hexdigest()
    metrics = json.loads((run_dir / "metrics.json").read_text(encoding="utf-8"))
    assert metrics["experiment"] == "coordinator_challenge_hardening_v1"
    assert set(metrics["layers"]) == {"wrapper", "challenge_verifier", "geometry", "sandbox"}
    assert (run_dir / "challenge_transcripts.jsonl").exists()
    redaction = json.loads((run_dir / "redaction.json").read_text(encoding="utf-8"))
    assert redaction["clean"] is True
