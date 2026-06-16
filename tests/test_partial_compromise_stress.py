"""Partial-compromise stress: matched-entropy arms, residual behavior, controls, artifacts."""

from __future__ import annotations

import hashlib
import json
import random
import tempfile
from pathlib import Path

from spatial_swarm.spatial_puzzle.experiments import partial_compromise_stress as PCS
from spatial_swarm.spatial_puzzle.experiments import pcs_access, pcs_metrics, pcs_systems


def _arms(seed=10_000):
    return pcs_systems.build_arms(random.Random(seed), n=3, k=4, swarm_id=f"t-{seed}", budget=(10.0, 3_000_000))


def test_arms_matched_entropy_within_alphabet_granularity():
    arms = _arms()
    em = arms["entropy_match"]
    # integer-alphabet granularity at small k limits the match; random_plus >= spatial bits
    assert em["random_plus_bits"] >= em["spatial_bits"] - 1e-9
    assert em["match_gap_bits"] < 1.5


def test_spatial_residual_non_increasing_under_stolen_neighbors():
    arms = _arms()
    table = pcs_access.residual_table(arms, budget=(10.0, 3_000_000))
    r0 = table["A0_public_only"]["arms"]["spatial"]
    r2 = table["A2_one_stolen_neighbor"]["arms"]["spatial"]
    r3 = table["A3_two_stolen_neighbors"]["arms"]["spatial"]
    assert r0["enumerated"] and r2["enumerated"] and r3["enumerated"]
    assert r0["residual_count"] >= r2["residual_count"] >= r3["residual_count"]


def test_random_factor_independent_of_access_level():
    arms = _arms()
    table = pcs_access.residual_table(arms, budget=(10.0, 3_000_000))
    probs = {
        lvl: table[lvl]["arms"]["random_plus"]["one_shot_success_prob"]
        for lvl in ("A0_public_only", "A2_one_stolen_neighbor", "A3_two_stolen_neighbors")
    }
    assert len(set(probs.values())) == 1  # stolen neighbors reveal nothing about an independent factor


def test_positive_controls_and_planted_secret():
    with tempfile.TemporaryDirectory() as td:
        pc = pcs_metrics.positive_controls(n=3, k=4, tmp_dir=Path(td))
        assert pc["valid"] is True
        assert all(v for k, v in pc.items() if k.startswith("control_"))
        planted = pcs_metrics.planted_secret_control(Path(td) / "planted")
        assert planted["detected"] is True


def test_sealed_runtime_fields():
    sr = PCS._sealed_runtime_demo()
    assert sr["sgx"] is False and sr["tee_attestation"] is False and sr["sealed_runtime"] == "process"
    assert sr["wrong_proof_destroyed"] and sr["second_attempt_denied"]


def test_end_to_end_tiny_run_artifacts_and_redaction(tmp_path: Path):
    run_dir = PCS.main(["--tier", "tiny", "--seeds", "4", "--output-root", str(tmp_path)])
    for name in ("metrics.json", "metrics.json.sha256", "config.yaml", "environment.txt",
                 "git_commit.txt", "events.jsonl", "solver_bakeoff.json",
                 "generator_rejection_histogram.json", "confidence_intervals.json",
                 "run_manifest.json", "summary.md", "redaction.json"):
        assert (run_dir / name).exists(), name
    digest = (run_dir / "metrics.json.sha256").read_text().strip()
    assert digest == hashlib.sha256((run_dir / "metrics.json").read_bytes()).hexdigest()
    m = json.loads((run_dir / "metrics.json").read_text())
    assert m["positive_controls"]["valid"] is True
    assert json.loads((run_dir / "redaction.json").read_text())["clean"] is True
    assert m["sealed_runtime"]["sgx"] is False
