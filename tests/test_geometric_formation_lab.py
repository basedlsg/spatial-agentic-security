"""Geometric Formation Lab v1 tests."""

from __future__ import annotations

from spatial_swarm.spatial_puzzle.geometry_lab.attacks import (
    AttackDefinition,
    mutate_for_attack,
)
from spatial_swarm.spatial_puzzle.geometry_lab.experiment import run_experiment
from spatial_swarm.spatial_puzzle.geometry_lab.families import (
    FAMILY_NAMES,
    generate_family_spec,
    leakage_bits_lost,
)
from spatial_swarm.spatial_puzzle.geometry_lab.verifier import (
    FULL_GEOMETRY,
    GeometryVerifier,
    PresentedFormation,
    config_for_ablation,
)


def test_all_geometry_families_generate_valid_formations():
    for family in FAMILY_NAMES:
        spec = generate_family_spec(family, 10, 0)
        decision = GeometryVerifier(FULL_GEOMETRY).verify(spec, PresentedFormation.from_spec(spec))
        assert decision.released is True, family
        assert decision.blocked is False, family


def test_braid_topology_ablation_exposes_wrong_braid():
    spec = generate_family_spec("braid", 10, 1)
    attack = AttackDefinition("same_endpoint_wrong_braid", "braid", ("topology",), ("braid",))
    presented = mutate_for_attack(PresentedFormation.from_spec(spec), attack, 1)
    full = GeometryVerifier(FULL_GEOMETRY).verify(spec, presented)
    no_topology = GeometryVerifier(config_for_ablation("no_topology")).verify(spec, presented)
    assert full.released is False
    assert "wrong_topology" in full.internal_reasons
    assert no_topology.released is True


def test_voronoi_leaks_more_than_braid_under_two_stolen_agents():
    voronoi = leakage_bits_lost("voronoi", "A3_two_stolen_agents", 20, 0)
    braid = leakage_bits_lost("braid", "A3_two_stolen_agents", 20, 0)
    assert voronoi > braid


def test_small_experiment_writes_core_metric_sections():
    metrics, csv_rows = run_experiment(
        families=("lattice", "braid", "voronoi"),
        agent_counts=(5, 10),
        trials=3,
        attack_trials=4,
        partial_compromise_trials=4,
        mutation_trials=3,
        ablation_trials=2,
    )
    assert metrics["config"]["v2_wrapper_fixed"] is True
    assert set(metrics["geometry_value"]) == {"lattice", "braid", "voronoi"}
    assert csv_rows["attack_matrix"]
    assert csv_rows["partial_compromise_leakage"]
    assert csv_rows["ablation_results"]
