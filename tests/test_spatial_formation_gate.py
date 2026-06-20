"""Spatial Formation Gate prototype experiment."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from spatial_swarm.spatial_puzzle.experiments import formation_gate as FG


def test_legitimate_high_risk_action_passes_all_arms():
    cfg = FG.FormationConfig()
    for arm_name in FG.ARM_NAMES:
        row = FG._run_legitimate(arm_name, cfg, 0)
        assert row["released"] == 1
        assert row["blocked"] == 0
        assert row["public_reason"] == "released"


def test_replay_changed_action_and_stolen_sidecar_fail_closed():
    cfg = FG.FormationConfig()
    for scenario in (
        "replay_old_formation",
        "changed_action_reuse",
        "same_nonce_reuse",
        "one_stolen_sidecar",
        "two_stolen_sidecars",
        "poisoned_tool_metadata_reuse",
    ):
        row = FG._run_attack("coordinated_formation", cfg, 0, scenario)
        assert row["released"] == 0
        assert row["blocked"] == 1
        assert row["killed_session"] == 1
        assert row["public_reason"] == "blocked"


def test_old_shared_residual_collapses_but_independent_arms_stay_flat():
    metrics = FG.run_experiment(trials=4)
    old = metrics["arms"]["old_shared_object"]["residual_under_partial_compromise"]
    assert old["target_bits_lost_A0_to_A3"] > 0
    for arm_name in (
        "random_baseline",
        "independent_static_geometry",
        "independent_trajectory",
        "coordinated_formation",
    ):
        block = metrics["arms"][arm_name]["residual_under_partial_compromise"]
        assert block["target_bits_lost_A0_to_A3"] == 0


def test_all_attack_scenarios_have_zero_observed_release_in_prototype():
    metrics = FG.run_experiment(trials=3)
    for arm in metrics["arms"].values():
        assert arm["legitimate_pass"]["rate"] == 1.0
        for attack in arm["attacks"].values():
            assert attack["unauthorized_release"]["rate"] == 0.0
            assert attack["blocked"]["rate"] == 1.0
            assert attack["timing_proxy_leak_bits"] == 0.0


def test_action_binding_and_same_nonce_reuse_are_measured():
    metrics = FG.run_experiment(trials=2)
    for row in metrics["action_binding"].values():
        assert row["legitimate_pass"]["rate"] == 1.0
        assert row["changed_action_reuse_release"]["rate"] == 0.0
        assert row["changed_action_same_nonce_reuse_release"]["rate"] == 0.0


def test_ablations_show_which_bindings_do_real_work():
    metrics = FG.run_experiment(trials=2)
    ablations = metrics["ablations"]
    assert ablations["full_geometry"]["path_near_miss_same_endpoint"]["release"]["rate"] == 0.0
    assert ablations["no_path_binding"]["path_near_miss_same_endpoint"]["release"]["rate"] == 1.0
    assert ablations["no_endpoint_binding"]["collision_or_endpoint_mutation"]["release"]["rate"] == 1.0
    assert ablations["no_action_binding"]["changed_action_same_nonce_reuse"]["release"]["rate"] == 0.0
    assert ablations["no_action_or_geometry_binding"]["changed_action_same_nonce_reuse"]["release"]["rate"] == 1.0
    assert ablations["no_nonce_binding"]["wrong_timing_nonce"]["release"]["rate"] == 1.0


def test_analysis_mode_blocks_without_shutdown():
    metrics = FG.run_experiment(trials=2)
    for row in metrics["analysis_mode_no_shutdown"].values():
        assert row["blocked"]["rate"] == 1.0
        assert row["session_survived_after_block"]["rate"] == 1.0


def test_cheap_attack_stress_runs_without_residual_solver():
    metrics = FG.run_experiment(trials=2, cheap_attack_trials=3)
    assert metrics["config"]["cheap_attack_trial_count"] == 3
    assert set(metrics["cheap_attack_stress"]) == set(FG.ATTACK_SCENARIOS)
    for row in metrics["cheap_attack_stress"].values():
        assert row["unauthorized_release"]["rate"] == 0.0
        assert row["blocked"]["rate"] == 1.0


def test_old_shared_target_selection_reports_weakest_agent():
    metrics = FG.run_experiment(trials=3)
    target_selection = metrics["arms"]["old_shared_object"]["residual_under_partial_compromise"][
        "target_selection"
    ]
    assert target_selection["sampled_trials"] == 3
    assert target_selection["easiest_agent_by_A0_to_A3_loss"]["bits_lost"] >= 0
    assert target_selection["hardest_agent_by_A0_to_A3_loss"]["bits_lost"] >= 0


def test_cli_writes_digest_and_clean_redaction(tmp_path: Path):
    run_dir = FG.main([
        "--trials", "2",
        "--diagnostic-trials", "2",
        "--timing-trials", "1",
        "--sweep-agents", "5,6",
        "--sweep-trials", "1",
        "--cheap-attack-trials", "2",
        "--output-root", str(tmp_path),
    ])
    digest = (run_dir / "metrics.json.sha256").read_text(encoding="utf-8").strip()
    assert digest == hashlib.sha256((run_dir / "metrics.json").read_bytes()).hexdigest()
    metrics = json.loads((run_dir / "metrics.json").read_text(encoding="utf-8"))
    assert metrics["experiment"] == "spatial_formation_gate_stress"
    assert set(metrics["agent_sweep"]) == {"5", "6"}
    assert metrics["config"]["cheap_attack_trial_count"] == 2
    redaction = json.loads((run_dir / "redaction.json").read_text(encoding="utf-8"))
    assert redaction["clean"] is True
