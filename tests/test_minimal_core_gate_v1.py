"""Minimal Core Gate v1 tests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from spatial_swarm.spatial_puzzle.experiments import minimal_core_gate_v1 as MCG

from _env_guards import needs_docker


def test_geometry_layer_blocks_auth_attack_and_no_geometry_releases_it():
    full = MCG.run_geometry_attack("fake_agent", 0, MCG.MinimalGuard(min_block_ms=0))
    assert full.blocked is True
    assert full.released is False
    no_geometry = MCG.run_geometry_attack(
        "fake_agent",
        0,
        MCG.MinimalGuard(geometry_enabled=False, min_block_ms=0),
    )
    assert no_geometry.released is True
    assert no_geometry.blocked is False


def test_effect_binding_and_transaction_binding_have_distinct_jobs():
    full_effect = MCG.run_effect_attack("read_file_writes_file", 0, MCG.MinimalGuard(min_block_ms=0))
    assert full_effect.effect_violation is True
    assert full_effect.blocked is True
    no_effect = MCG.run_ablation_case("no_effect_binding", 0, MCG.MinimalGuard(min_block_ms=0))
    assert no_effect.released is True
    assert no_effect.effect_violation is True

    full_tx = MCG.run_transaction_scenario("mid_transaction_swap", 0, MCG.MinimalGuard(min_block_ms=0))
    assert full_tx.blocked is True
    no_tx = MCG.run_ablation_case("no_transaction_binding", 0, MCG.MinimalGuard(min_block_ms=0))
    assert no_tx.released is True
    assert no_tx.transaction_swap_released is True


@needs_docker
def test_boundary_ablations_expose_target_controls():
    cfg = MCG.MinimalGuard(min_block_ms=0)
    assert MCG.run_boundary_attack("shell_command", 0, cfg).blocked is True
    assert MCG.run_ablation_case("no_command_allowlist", 0, cfg).command_injection_released is True
    assert MCG.run_boundary_attack("path_traversal", 0, cfg).blocked is True
    assert MCG.run_ablation_case("no_path_canonicalization", 0, cfg).path_escape_released is True
    assert MCG.run_ablation_case("no_network_isolation", 0, cfg).unapproved_network_released is True


@needs_docker
def test_tiny_cli_run_writes_digest_and_clean_redaction(tmp_path: Path):
    run_dir = MCG.main(
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
    assert metrics["experiment"] == "minimal_core_gate_v1"
    assert set(metrics["layers"]) == {"wrapper", "sandbox", "geometry"}
    redaction = json.loads((run_dir / "redaction.json").read_text(encoding="utf-8"))
    assert redaction["clean"] is True
