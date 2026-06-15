"""Protocol-agnostic fail-closed evaluation kit."""

from __future__ import annotations

import json

import pytest

from spatial_swarm.evalkit import (
    AttackerCapability,
    RoundOutcome,
    UCOGGate,
    USAGGate,
    evaluate_gate,
)

SEEDS = range(5000, 5008)


@pytest.mark.parametrize("gate", [USAGGate(), UCOGGate()], ids=["usag", "ucog"])
def test_reference_gates_fail_closed(gate):
    report = evaluate_gate(gate, seeds=SEEDS)
    assert report.honest_releases == report.trials
    assert report.redaction_clean
    for cap in report.capabilities.values():
        if cap.is_positive_control:
            assert cap.unauthorized_releases == cap.trials  # control releases
            assert cap.secret_leaks == cap.trials
        else:
            assert cap.unauthorized_releases == 0           # real attack blocked
            assert cap.release_rate_ci95["high"] < 0.5


def test_reports_have_uniform_shape():
    usag = evaluate_gate(USAGGate(), seeds=SEEDS)
    ucog = evaluate_gate(UCOGGate(), seeds=SEEDS)
    assert set(usag.capabilities) == set(ucog.capabilities)
    # both serialize to JSON
    json.dumps(usag.to_dict())
    json.dumps(ucog.to_dict())


class AlwaysOpenGate:
    """A gate with no fail-closed behavior: releases everything."""

    name = "always_open"

    def honest_round(self, agent_count, fragment_size, seed) -> RoundOutcome:
        return RoundOutcome(passed=True)

    def attack_round(self, agent_count, fragment_size, seed, capability) -> RoundOutcome:
        return RoundOutcome(passed=True, secret_leaked=capability.is_positive_control)

    def artifact_text(self, agent_count, fragment_size, seed) -> str:
        return ""


def test_kit_flags_a_non_fail_closed_gate():
    report = evaluate_gate(AlwaysOpenGate(), seeds=SEEDS)
    # honest still releases, but so do the real attacks -> the kit shows it is not fail-closed
    for cap in report.capabilities.values():
        if not cap.is_positive_control:
            assert cap.unauthorized_releases == cap.trials
            assert cap.release_rate_ci95["low"] > 0.5


def test_custom_capability_set():
    report = evaluate_gate(
        UCOGGate(),
        seeds=SEEDS,
        capabilities=(AttackerCapability("signing_key_only", has_signing_authority=True),),
    )
    assert set(report.capabilities) == {"signing_key_only"}
    assert report.capabilities["signing_key_only"].unauthorized_releases == 0
