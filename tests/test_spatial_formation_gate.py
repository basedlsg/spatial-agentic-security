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


def test_cli_writes_digest_and_clean_redaction(tmp_path: Path):
    run_dir = FG.main(["--trials", "2", "--output-root", str(tmp_path)])
    digest = (run_dir / "metrics.json.sha256").read_text(encoding="utf-8").strip()
    assert digest == hashlib.sha256((run_dir / "metrics.json").read_bytes()).hexdigest()
    metrics = json.loads((run_dir / "metrics.json").read_text(encoding="utf-8"))
    assert metrics["experiment"] == "spatial_formation_gate_stress"
    redaction = json.loads((run_dir / "redaction.json").read_text(encoding="utf-8"))
    assert redaction["clean"] is True
