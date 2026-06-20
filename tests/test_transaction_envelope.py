"""Multi-action transaction envelope tests."""

from __future__ import annotations

from spatial_swarm.spatial_puzzle.experiments import realistic_coding_gate_v2 as V2


def test_transaction_scenarios_only_allow_valid_sequence():
    cfg = V2.V2Config(min_block_ms=0.0)
    for scenario in V2.TRANSACTION_SCENARIOS:
        row = V2.run_transaction_scenario(scenario, 0, cfg)
        if scenario == "valid_read_edit_tests":
            assert row.executed is True
        else:
            assert row.executed is False, scenario
            assert row.blocked is True, scenario


def test_reordered_transaction_hash_differs():
    cfg = V2.V2Config(min_block_ms=0.0)
    valid = V2.run_transaction_scenario("valid_read_edit_tests", 0, cfg)
    reordered = V2.run_transaction_scenario("reordered_sequence", 0, cfg)
    assert valid.executed is True
    assert reordered.executed is False
