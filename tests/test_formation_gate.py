"""Formation gate tests independent of policy validity."""

from __future__ import annotations

from spatial_swarm.spatial_puzzle.experiments import realistic_coding_gate_v2 as V2


def test_formation_attacks_block_when_policy_allows_action():
    cfg = V2.V2Config(min_block_ms=0.0)
    for attack in V2.FORMATION_ATTACKS:
        raw = V2._default_raw("credential_read" if attack in {"stolen_sidecar", "coordinator_forgery"} else "edit_file")
        row = V2.attempt_action(raw, scenario=attack, trial_index=0, config=cfg, formation_attack=attack)
        assert row.policy_allowed is True, attack
        assert row.executed is False, attack


def test_valid_formation_executes_allowed_action():
    row = V2.attempt_action(
        V2._default_raw("edit_file"),
        scenario="valid",
        trial_index=0,
        config=V2.V2Config(min_block_ms=0.0),
    )
    assert row.policy_allowed is True
    assert row.formation_released is True
    assert row.executed is True
