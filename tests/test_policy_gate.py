"""Policy gate tests independent of formation validity."""

from __future__ import annotations

from spatial_swarm.spatial_puzzle.experiments import realistic_coding_gate_v2 as V2


def test_policy_matrix_only_allows_valid_policy_and_valid_formation():
    metrics = V2.policy_matrix(2, V2.V2Config(min_block_ms=0.0))
    assert metrics["valid_policy_valid_formation"]["executed"]["rate"] == 1.0
    assert metrics["valid_policy_invalid_formation"]["executed"]["rate"] == 0.0
    assert metrics["invalid_policy_valid_formation"]["executed"]["rate"] == 0.0
    assert metrics["invalid_policy_invalid_formation"]["executed"]["rate"] == 0.0


def test_policy_blocks_disallowed_action_even_before_formation():
    row = V2.attempt_action(
        V2.RawAction("read_file", "../../outside.txt"),
        scenario="path_escape",
        trial_index=0,
        config=V2.V2Config(min_block_ms=0.0),
    )
    assert row.policy_allowed is False
    assert row.formation_released is False
    assert row.executed is False
