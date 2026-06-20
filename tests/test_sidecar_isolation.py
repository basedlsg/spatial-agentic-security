"""Sidecar isolation surface tests."""

from __future__ import annotations

from spatial_swarm.spatial_puzzle.experiments import realistic_coding_gate_v2 as V2


def test_sidecar_leakage_surfaces_do_not_execute():
    cfg = V2.V2Config(min_block_ms=0.0)
    for scenario in V2.SIDECAR_ATTACKS:
        row = V2.run_sidecar_attack(scenario, 0, cfg)
        assert row.executed is False, scenario
        assert row.public_reason == "blocked", scenario
        assert row.public_log_bytes == cfg.public_log_bytes, scenario


def test_repeated_oracle_call_cannot_fake_missing_agents():
    row = V2.run_sidecar_attack("repeated_oracle_calls", 0, V2.V2Config(min_block_ms=0.0))
    assert row.formation_released is False
    assert row.executed is False
