"""Keystone experiment: does USAG's geometry add anything over a fair baseline?

Encodes the honest result as a regression-proof invariant: a fully-executed,
UNANIMOUS commitment-opening gate (UCOG, no geometry) makes the SAME pass/fail
decision as full USAG on every scenario -- including the multi-agent / assembly
class (correct_geometry_wrong_agent_id, duplicate, partial_swarm, missing), which
are the only scenarios where a unanimous gate could differ from a single-agent
one. The geometry's marginal advantage over the fair baseline is zero.
"""

from __future__ import annotations

import pytest

from spatial_swarm.experiments.fair_baselines import (
    run_fair_baseline_matrix,
    spec_for,
)

# Scenarios the metadata-only signature gate misses but USAG catches -- the
# apparent "spatial advantage". UCOG (no geometry) must catch all of them.
SIGNATURE_GATE_MISSES = (
    "valid_signature_wrong_geometry",
    "valid_signature_wrong_transform",
    "stolen_signing_authority_only",
    "verifier_snapshot_forgery",
    "correct_geometry_wrong_agent_id",
    "duplicate",
)

# The multi-agent / assembly class the fairness audit demanded be included.
ASSEMBLY_CLASS = ("correct_geometry_wrong_agent_id", "duplicate", "partial_swarm", "missing")


def test_ucog_matches_usag_on_all_keystone_scenarios():
    m = run_fair_baseline_matrix(agent_count=8, fragment_size=16, seed=1337)
    assert m["ucog_matches_usag_on_all_scenarios"] is True
    assert m["geometry_marginal_advantage_count"] == 0


def test_signature_gate_is_beaten_exactly_where_expected():
    m = run_fair_baseline_matrix(seed=1337)
    assert set(m["scenarios_where_signature_gate_is_beaten"]) == set(SIGNATURE_GATE_MISSES)
    # and the non-geometric gate catches every one of them
    assert set(m["scenarios_where_ucog_also_catches"]) == set(SIGNATURE_GATE_MISSES)


@pytest.mark.parametrize("scenario", SIGNATURE_GATE_MISSES)
def test_metadata_signature_misses_but_ucog_and_usag_catch(scenario):
    m = run_fair_baseline_matrix(seed=1337)
    cell = m["matrix"][scenario]
    assert cell["unanimous_signature_metadata"]["passed"] is True   # signature gate fooled
    assert cell["unanimous_commitment_opening"]["passed"] is False  # fair baseline catches
    assert cell["usag_full"]["passed"] is False                     # USAG catches


@pytest.mark.parametrize("scenario", ASSEMBLY_CLASS)
def test_assembly_class_caught_by_ucog_and_usag(scenario):
    """The multi-agent class that could distinguish a unanimous gate -- but UCOG
    (no geometry) catches it identically to USAG."""

    m = run_fair_baseline_matrix(seed=1337)
    cell = m["matrix"][scenario]
    assert cell["unanimous_commitment_opening"]["passed"] is False
    assert cell["usag_full"]["passed"] is False
    # and the failure reasons agree (same mechanism, no geometry needed)
    assert (
        cell["unanimous_commitment_opening"]["reason"] == cell["usag_full"]["reason"]
    )


def test_honest_passes_every_gate():
    m = run_fair_baseline_matrix(seed=1337)
    for gate in m["gates"]:
        assert m["matrix"]["honest"][gate]["passed"] is True


@pytest.mark.parametrize("seed", [7, 99, 1337, 20240])
def test_invariant_holds_across_seeds(seed):
    m = run_fair_baseline_matrix(agent_count=6, fragment_size=8, seed=seed)
    assert m["ucog_matches_usag_on_all_scenarios"] is True
    assert m["geometry_marginal_advantage_count"] == 0


def test_baseline_attacks_fail_closed_in_every_gate():
    m = run_fair_baseline_matrix(seed=1337)
    for scenario in ("fake_agent", "unregistered_fake_agent", "replay", "stolen_fragment_only"):
        for gate in m["gates"]:
            assert m["matrix"][scenario][gate]["passed"] is False, (scenario, gate)


def test_unknown_scenario_raises_no_silent_fallthrough():
    with pytest.raises(ValueError):
        spec_for("some_unmapped_scenario")
