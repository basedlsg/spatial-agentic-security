"""Leakage meter: monotonic residual collapse, all <= random ceiling."""

from __future__ import annotations

from spatial_swarm.spatial_puzzle.leakage.meter import measure_ladder

M = measure_ladder(n=3, k=4, seeds=12, alphabet_size=4, seed_base=2000)


def test_ceiling_is_outer_shape_level():
    assert M["random_ceiling"]["label"] == "O1_outer_shape"
    assert M["random_ceiling"]["residual_median"] is not None


def test_residual_monotonic_under_more_clues_and_neighbors():
    med = {lbl: M["levels"][lbl]["residual_median"] for lbl in M["levels"] if M["levels"][lbl].get("residual_median")}
    s = med["O1_outer_shape"]
    # adding lossy clues never increases the candidate set
    assert med["O7_connector_hint"] <= s
    assert med["O8_topology_hint"] <= s
    assert med["O7O8_both_hints"] <= med["O7_connector_hint"]
    assert med["O7O8_both_hints"] <= med["O8_topology_hint"]
    # revealing neighbors never increases it
    assert med["O3_one_neighbor"] <= s
    assert med["O4_all_neighbors"] <= med["O3_one_neighbor"]


def test_all_neighbors_pins_the_piece():
    # revealing every other piece leaves the complement -> a single candidate
    assert M["levels"]["O4_all_neighbors"]["residual_median"] == 1


def test_spatial_never_exceeds_random_ceiling():
    ceiling = M["random_ceiling"]["residual_median"]
    for lbl, cell in M["levels"].items():
        if cell.get("residual_median") is not None:
            assert cell["residual_median"] <= ceiling, lbl
            # delta below the ceiling is >= 0 (structure only reduces uncertainty)
            d = cell.get("delta_below_random_ceiling_bits")
            if d is not None:
                assert d >= -1e-9


def test_one_shot_prob_rises_as_residual_falls():
    both = M["levels"]["O7O8_both_hints"]
    shape = M["levels"]["O1_outer_shape"]
    assert both["one_shot_success_prob_median"] >= shape["one_shot_success_prob_median"]
