"""Optional-solver import firewall."""

from __future__ import annotations

from spatial_swarm.spatial_puzzle.solvers import optional


def test_availability_keys_present():
    assert set(optional.AVAILABILITY) == {"cp_sat", "sat", "smt", "graph_iso"}


def test_available_returns_bool_and_defaults_true_for_unknown():
    for name in optional.AVAILABILITY:
        assert isinstance(optional.available(name), bool)
    assert optional.available("nonexistent_solver") is True  # unknown -> not gated


def test_available_solver_has_no_import_error():
    # In this environment the four solver wheels are installed; if one were missing,
    # available() would be False and import_error() would carry the reason.
    for name in optional.AVAILABILITY:
        if optional.available(name):
            assert optional.import_error(name) is None
            assert optional.module(name) is not None
