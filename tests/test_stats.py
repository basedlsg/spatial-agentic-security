"""Exact binomial (Clopper-Pearson) confidence intervals."""

from __future__ import annotations

import pytest

from spatial_swarm.experiments.stats import (
    clopper_pearson,
    regularized_incomplete_beta,
)


def test_boundary_zero_successes():
    low, high = clopper_pearson(0, 1000)
    assert low == 0.0
    assert high == pytest.approx(0.00368, abs=1e-4)  # ~ rule of three


def test_boundary_all_successes():
    low, high = clopper_pearson(1000, 1000)
    assert high == 1.0
    assert low == pytest.approx(0.99632, abs=1e-4)


@pytest.mark.parametrize(
    "successes,n,expected",
    [
        (5, 100, (0.0164, 0.1128)),
        (50, 100, (0.3983, 0.6017)),
        (0, 10, (0.0, 0.3085)),
    ],
)
def test_known_interior_values(successes, n, expected):
    low, high = clopper_pearson(successes, n)
    assert low == pytest.approx(expected[0], abs=1e-3)
    assert high == pytest.approx(expected[1], abs=1e-3)


def test_interval_contains_point_estimate():
    for successes, n in [(0, 50), (50, 50), (7, 33), (1, 1000)]:
        low, high = clopper_pearson(successes, n)
        p = successes / n
        assert low <= p <= high


def test_regularized_incomplete_beta_endpoints():
    assert regularized_incomplete_beta(2, 3, 0.0) == 0.0
    assert regularized_incomplete_beta(2, 3, 1.0) == 1.0
    assert regularized_incomplete_beta(1, 1, 0.5) == pytest.approx(0.5, abs=1e-6)


def test_invalid_successes():
    with pytest.raises(ValueError):
        clopper_pearson(11, 10)


def test_summarize_results_includes_ci():
    from spatial_swarm.experiments.runner import run_honest

    results = [run_honest(4, 8, 100 + i, None) for i in range(5)]
    from spatial_swarm.experiments.metrics import summarize_results

    summary = summarize_results(results, "honest")
    assert "pass_rate_ci95" in summary
    assert set(summary["pass_rate_ci95"]) == {"low", "high"}
    assert summary["pass_rate_ci95"]["low"] <= summary["pass_rate"] <= summary["pass_rate_ci95"]["high"]
