"""v0.6 process-sidecar shutdown scenario and benchmark wiring."""

from __future__ import annotations

from spatial_swarm.experiments.runner import (
    BENCHMARK_PRESETS,
    SCENARIO_GROUPS,
    SCENARIOS,
    normalize_argv,
    run_process_sidecar_shutdown,
)


def test_post_shutdown_send_fails_closed():
    result = run_process_sidecar_shutdown(4, 4, 911, None)
    assert not result.passed
    assert result.failure_reason == "sidecar_shutdown_enforced"
    assert result.collapsed


def test_v0_6_process_group_includes_shutdown():
    group = SCENARIO_GROUPS["v0_6_process_sidecar"]
    assert group == [
        "process_sidecar_honest",
        "process_sidecar_fake_agent",
        "process_sidecar_replay",
        "process_sidecar_shutdown",
    ]
    for name in group:
        assert name in SCENARIOS


def test_v0_6_benchmark_aliases_resolve():
    assert normalize_argv(["benchmark", "v0_6_ai_forgery"]) == [
        "--scenario",
        "ai_forgery_matrix",
        "--agents",
        "4",
        "--attempts",
        "100",
    ]
    assert "v0_6_focused" in BENCHMARK_PRESETS
    assert "v0_6_snapshot_forgery" in BENCHMARK_PRESETS
