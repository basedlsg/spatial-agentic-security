"""Effect binding tests for Real Sandbox Gate v3."""

from __future__ import annotations

from spatial_swarm.spatial_puzzle.experiments import real_sandbox_gate_v3 as V3
from spatial_swarm.spatial_puzzle.sandbox.results import EffectRecord


def test_effect_record_subset_rule_catches_extra_file_write():
    allowed = EffectRecord(files_read=("README.md",))
    actual = EffectRecord(files_read=("README.md",), files_written=("src/app.py",))
    assert actual.exceeds(allowed) is True
    assert allowed.exceeds(actual) is False


def test_effect_mismatch_blocks_and_no_effect_binding_releases():
    full = V3.run_attack_case("read_file_writes_file", 0, V3.GuardConfig(min_block_ms=0))
    assert full.blocked is True
    assert full.effect_violation is True
    ablated = V3.run_ablation_case("no_effect_binding", 0, V3.GuardConfig(min_block_ms=0))
    assert ablated.released is True
    assert ablated.effect_violation is True
