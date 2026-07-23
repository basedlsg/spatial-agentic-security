"""Transaction binding tests for Real Sandbox Gate v3."""

from __future__ import annotations

import pytest

from spatial_swarm.spatial_puzzle.experiments import real_sandbox_gate_v3 as V3

# The cases that actually execute containers need a working Docker backend + image.
_needs_docker = pytest.mark.skipif(
    not V3._docker_info().get("available", False),
    reason="requires a working Docker sandbox backend + container image",
)


@_needs_docker
def test_valid_transaction_releases_and_reordered_transaction_blocks():
    cfg = V3.GuardConfig(min_block_ms=0)
    valid = V3.run_transaction_scenario("valid_read_edit_tests", 0, cfg)
    assert valid.released is True
    reordered = V3.run_transaction_scenario("reordered_sequence", 0, cfg)
    assert reordered.blocked is True
    assert reordered.released is False


def test_no_transaction_binding_releases_mid_transaction_swap():
    row = V3.run_ablation_case("no_transaction_binding", 0, V3.GuardConfig(min_block_ms=0))
    assert row.released is True
    assert row.transaction_swap_released is True
