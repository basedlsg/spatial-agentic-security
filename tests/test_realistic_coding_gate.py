"""Realistic Coding Gate experiment tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from spatial_swarm.spatial_puzzle.experiments import realistic_coding_gate as RCG


def test_valid_real_actions_execute_and_wrong_formations_do_not():
    cfg = RCG.RealisticGateConfig()
    metrics = RCG._real_action_suite_metrics(cfg, trials=1)
    for action, row in metrics.items():
        assert row["valid"]["release"]["rate"] == 1.0, action
        assert row["valid"]["executed"]["rate"] == 1.0, action
        assert row["wrong_formation_release"]["rate"] == 0.0, action
        assert row["wrong_formation"]["executed"]["rate"] == 0.0, action


def test_policy_blocks_delete_repo_even_with_correct_formation():
    cfg = RCG.RealisticGateConfig()
    row = RCG.RealisticCodingGate(cfg, 0).attempt(
        scenario="delete_repo",
        execute_action=RCG._delete_repo_action(),
    )
    assert row.blocked is True
    assert row.executed is False
    assert "policy:single_file_delete_only" in row.internal_reasons
    assert row.public_reason == "blocked"


def test_action_reuse_for_dangerous_execution_is_blocked():
    cfg = RCG.RealisticGateConfig()
    actions = RCG._real_action_suite()
    row = RCG.RealisticCodingGate(cfg, 1).attempt(
        scenario="read_for_credential",
        proof_action=actions["read_file"],
        execute_action=actions["credential_read"],
    )
    assert row.released is False
    assert row.executed is False
    assert any(reason.endswith("execution_action_mismatch") for reason in row.internal_reasons)


def test_constant_failure_public_shape_is_single_shape():
    cfg = RCG.RealisticGateConfig(pad_blocked_ms=0.0)
    metrics = RCG._constant_failure_metrics(cfg, trials=1)
    assert metrics["constant_failure_passed"] is True
    assert metrics["combined"]["visible_shape_count"] == 1
    assert metrics["combined"]["release"]["rate"] == 0.0


def test_ablation_rows_show_expected_release_when_binding_removed():
    cfg = RCG.RealisticGateConfig(pad_blocked_ms=0.0)
    metrics = RCG._ablation_metrics(cfg, trials=1)
    assert metrics["full_gate"]["max_release"] == 0.0
    assert metrics["no_nonce_binding"]["max_release"] == 1.0
    assert metrics["no_path_binding"]["max_release"] == 1.0
    assert metrics["no_endpoint_binding"]["max_release"] == 1.0
    assert metrics["no_required_agent_binding"]["max_release"] == 1.0
    assert metrics["no_timing_binding"]["max_release"] == 1.0


def test_geometry_value_ladder_reports_less_geometry_as_weaker():
    cfg = RCG.RealisticGateConfig(pad_blocked_ms=0.0)
    metrics = RCG._geometry_value_metrics(cfg, trials=1)
    assert metrics["hmac_only"]["max_attack_release"] == 1.0
    assert metrics["full_gate"]["max_attack_release"] == 0.0


def test_cli_writes_digest_and_clean_redaction(tmp_path: Path):
    run_dir = RCG.main([
        "--trials", "1",
        "--attack-trials", "1",
        "--timing-trials", "1",
        "--ablation-trials", "1",
        "--geometry-trials", "1",
        "--sweep-trials", "1",
        "--sweep-agents", "5,10",
        "--pad-blocked-ms", "0",
        "--output-root", str(tmp_path),
    ])
    digest = (run_dir / "metrics.json.sha256").read_text(encoding="utf-8").strip()
    assert digest == hashlib.sha256((run_dir / "metrics.json").read_bytes()).hexdigest()
    metrics = json.loads((run_dir / "metrics.json").read_text(encoding="utf-8"))
    assert metrics["experiment"] == "realistic_coding_gate_v1"
    assert set(metrics["swarm_sweep"]) == {"5", "10"}
    redaction = json.loads((run_dir / "redaction.json").read_text(encoding="utf-8"))
    assert redaction["clean"] is True
