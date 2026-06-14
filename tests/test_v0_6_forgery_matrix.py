"""v0.6 forgery harness: AI/inference levels, snapshot boundaries, controls."""

from __future__ import annotations

import pytest

from spatial_swarm.attacks.forgery_harness import (
    AI_FORGERY_KINDS,
    POSITIVE_CONTROL_ORDER,
    SNAPSHOT_FORGERY_KINDS,
    ProviderResponse,
    run_forgery_round,
)

AGENTS = 4
FRAGMENT = 8
SEED = 4321


# Expected fail-closed stage for each non-control attacker. Attackers without
# signing authority die at the signature layer; attackers with stolen signing
# authority but no fragment die at the geometry layer.
EXPECTED_FAILURE_STAGE = {
    "ai_level_0_protocol_only": "signature",
    "ai_level_1_signing_authority": "geometry",
    "ai_level_2_many_observations": "geometry",
    "ai_level_3_partial_compromise": "geometry",
    "snapshot_verifier_public_state": "signature",
    "snapshot_verifier_public_state_with_signing_authority": "geometry",
    "snapshot_old_packets_only": "signature",
    "snapshot_run_artifacts": "signature",
}


@pytest.mark.parametrize("kind", [*AI_FORGERY_KINDS, *SNAPSHOT_FORGERY_KINDS])
def test_forgery_attackers_fail_closed(kind: str):
    outcome = run_forgery_round(
        agent_count=AGENTS, fragment_size=FRAGMENT, seed=SEED, kind=kind
    )

    assert not outcome.message_passed, f"{kind} unexpectedly released a message"
    assert not outcome.secret_extracted, f"{kind} unexpectedly extracted a secret"
    assert not outcome.raw_secret_in_view, f"{kind} surfaced a raw secret marker"
    assert not outcome.verifier_crashed
    assert outcome.failure_stage == EXPECTED_FAILURE_STAGE[kind]


def test_signing_authority_attackers_reach_the_geometry_layer():
    """Granting a stolen signing key is the stronger attacker: it must clear the
    signature layer and be stopped only by the spatial/commitment check."""

    outcome = run_forgery_round(
        agent_count=AGENTS,
        fragment_size=FRAGMENT,
        seed=SEED,
        kind="ai_level_2_many_observations",
    )
    assert outcome.failure_reason == "wrong_geometry"
    # Many prior observations do not help: the move is still a blind guess.
    assert outcome.inference_method == "uniform_random_guess_from_public_commitment"


@pytest.mark.parametrize("kind", POSITIVE_CONTROL_ORDER)
def test_positive_controls_break_through(kind: str):
    """Controls prove the harness can detect a real forgery and pin USAG's
    hardness to cryptography (commitment + encryption), not geometry secrecy."""

    outcome = run_forgery_round(
        agent_count=AGENTS, fragment_size=FRAGMENT, seed=SEED, kind=kind
    )
    assert outcome.message_passed, f"control {kind} should have released a message"
    assert outcome.secret_extracted
    assert outcome.is_positive_control


def test_geometry_leak_control_uses_transform_inversion():
    outcome = run_forgery_round(
        agent_count=AGENTS,
        fragment_size=FRAGMENT,
        seed=SEED,
        kind="control_geometry_leak",
    )
    assert outcome.inference_method == "transform_inversion_from_leaked_geometry"


def test_outcomes_are_deterministic():
    a = run_forgery_round(agent_count=AGENTS, fragment_size=FRAGMENT, seed=99, kind="ai_level_1_signing_authority")
    b = run_forgery_round(agent_count=AGENTS, fragment_size=FRAGMENT, seed=99, kind="ai_level_1_signing_authority")
    assert (a.failure_reason, a.failure_stage, a.output) == (
        b.failure_reason,
        b.failure_stage,
        b.output,
    )


def test_attempt_records_all_required_fields():
    outcome = run_forgery_round(
        agent_count=AGENTS, fragment_size=FRAGMENT, seed=SEED, kind="ai_level_1_signing_authority"
    )
    record = outcome.to_log_dict()
    required = {
        "model",
        "provider",
        "prompt",
        "temperature",
        "max_tokens",
        "output",
        "output_tokens",
        "latency_ms",
        "parse_result",
        "failure_reason",
        "failure_stage",
        "message_passed",
        "secret_extracted",
        "verifier_crashed",
    }
    assert required.issubset(record)
    assert record["model"] == "programmatic_optimal"
    assert record["prompt"]  # non-empty task description


def test_pluggable_model_provider_output_is_recorded_verbatim():
    """A real model only outputs candidate coords; the harness owns crypto and
    must store the raw model output without rewriting a failed attempt."""

    raw_output = "MODEL SAYS: my best guess <<unparsed junk kept as-is>>"

    def fake_model_provider(view, prompt) -> ProviderResponse:
        coords = [
            ((i + 1) % view.p, (2 * i + 1) % view.p, (3 * i + 1) % view.p)
            for i in range(view.target_fragment_size)
        ]
        return ProviderResponse(
            coords=coords,
            raw_output=raw_output,
            model="fake-model-x",
            provider="unit_test",
            temperature=0.7,
            max_tokens=256,
            output_tokens=42,
            latency_ms=12.5,
            parse_result="ok",
            inference_method="model_freeform_guess",
        )

    outcome = run_forgery_round(
        agent_count=AGENTS,
        fragment_size=FRAGMENT,
        seed=SEED,
        kind="ai_level_1_signing_authority",
        provider=fake_model_provider,
    )
    assert outcome.model == "fake-model-x"
    assert outcome.output == raw_output  # verbatim, not rewritten
    assert not outcome.message_passed
    assert outcome.failure_reason == "wrong_geometry"
