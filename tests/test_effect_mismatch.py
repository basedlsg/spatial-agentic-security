"""Effect mismatch attack tests."""

from __future__ import annotations

from spatial_swarm.spatial_puzzle.experiments import realistic_coding_gate_v2 as V2


def test_effect_mismatches_do_not_execute_silently():
    cfg = V2.V2Config(min_block_ms=0.0)
    for scenario in V2.EFFECT_MISMATCH_ATTACKS:
        row = V2.run_effect_mismatch(scenario, 0, cfg)
        assert row.effect_violation is True, scenario
        assert row.executed is False, scenario
        assert row.blocked is True, scenario


def test_effect_binding_ladder_exposes_no_effect_binding_variant():
    metrics = V2.geometry_effect_ladder(2, V2.V2Config(min_block_ms=0.0))
    assert metrics["full_gate_with_effect_binding"]["effect_mismatch"]["executed"]["rate"] == 0.0
    assert metrics["full_gate_no_effect_binding"]["effect_mismatch"]["executed"]["rate"] == 1.0
