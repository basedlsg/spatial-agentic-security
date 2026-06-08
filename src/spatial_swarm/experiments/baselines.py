"""Baseline gate modes for reviewer-facing comparisons."""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import Any

from nacl.signing import SigningKey

from spatial_swarm.core.gateway import Gateway
from spatial_swarm.core.message import FrozenMessage, freeze_message
from spatial_swarm.crypto.hashing import hash_bytes
from spatial_swarm.crypto.signatures import sign_payload, verify_payload


BASELINE_MODES = (
    "mode_0_no_gate",
    "mode_1_sender_signature_only",
    "mode_2_unanimous_signature_gate",
)


@dataclass(frozen=True)
class BaselineResult:
    mode: str
    scenario: str
    passed: bool
    reason: str
    latency_ms: float
    unauthorized: bool


@dataclass(frozen=True)
class ScenarioProfile:
    registered_sender: bool = True
    valid_sender_signature: bool = True
    valid_unanimous_signatures: bool = True
    valid_message_binding: bool = True
    fresh_message: bool = True
    requires_spatial_gate: bool = False


def evaluate_baseline_mode(
    mode: str,
    scenario: str,
    gateway: Gateway,
    sender_id: str = "agent_001",
    receiver_id: str = "agent_002",
    content: Any | None = None,
) -> BaselineResult:
    started = time.perf_counter()
    profile = scenario_profile(scenario)
    payload_content = {"body": "baseline"} if content is None else content
    message = freeze_message(sender_id, receiver_id, gateway.epoch, payload_content, nonce="current")
    old_message = freeze_message(sender_id, receiver_id, gateway.epoch, payload_content, nonce="old")
    unsigned_sender = "agent_999" if not profile.registered_sender else sender_id
    unauthorized = scenario != "honest"

    if mode == "mode_0_no_gate":
        return _result(mode, scenario, True, "no_membership_or_signature_gate", started, unauthorized)
    if mode == "mode_1_sender_signature_only":
        return _sender_signature_gate(
            mode,
            scenario,
            gateway,
            unsigned_sender,
            message,
            old_message,
            profile,
            started,
            unauthorized,
        )
    if mode == "mode_2_unanimous_signature_gate":
        return _unanimous_signature_gate(
            mode,
            scenario,
            gateway,
            message,
            old_message,
            profile,
            started,
            unauthorized,
        )
    raise ValueError(f"unknown baseline mode {mode!r}")


def scenario_profile(scenario: str) -> ScenarioProfile:
    canonical = _canonical_scenario(scenario)
    if canonical == "honest":
        return ScenarioProfile()
    if canonical in {"fake_agent", "stolen_fragment_only"}:
        return ScenarioProfile(valid_sender_signature=False, valid_unanimous_signatures=False)
    if canonical == "unregistered_fake_agent":
        return ScenarioProfile(
            registered_sender=False,
            valid_sender_signature=False,
            valid_unanimous_signatures=False,
        )
    if canonical in {"replay", "wrong_message", "valid_signature_wrong_message_hash"}:
        return ScenarioProfile(valid_message_binding=False, fresh_message=False)
    if canonical in {
        "valid_signature_wrong_geometry",
        "valid_signature_wrong_transform",
        "stolen_signing_key_only",
        "stolen_signing_authority_only",
        "correct_geometry_wrong_agent_id",
        "all_but_one_valid_spatial_piece",
    }:
        return ScenarioProfile(requires_spatial_gate=True)
    if canonical in {
        "overbudget",
        "underbudget",
        "malformed",
        "slow",
        "missing",
        "partial_swarm",
        "stolen_piece",
        "duplicate",
    }:
        return ScenarioProfile(requires_spatial_gate=True)
    if canonical.startswith("fuzz_"):
        return ScenarioProfile(
            valid_sender_signature=False,
            valid_unanimous_signatures=False,
            requires_spatial_gate=True,
        )
    return ScenarioProfile(requires_spatial_gate=True)


def summarize_baseline_results(results: list[BaselineResult]) -> dict[str, Any]:
    by_mode: dict[str, dict[str, Any]] = {}
    by_scenario: dict[str, dict[str, Any]] = {}
    for result in results:
        mode_bucket = by_mode.setdefault(
            result.mode,
            {
                "attempts": 0,
                "passes": 0,
                "unauthorized_attempts": 0,
                "unauthorized_passes": 0,
                "reasons": {},
                "latency_ms": [],
            },
        )
        scenario_bucket = by_scenario.setdefault(
            result.scenario,
            {"attempts": 0, "passes_by_mode": {}, "reasons_by_mode": {}},
        )
        mode_bucket["attempts"] += 1
        mode_bucket["passes"] += int(result.passed)
        mode_bucket["unauthorized_attempts"] += int(result.unauthorized)
        mode_bucket["unauthorized_passes"] += int(result.passed and result.unauthorized)
        mode_bucket["reasons"][result.reason] = mode_bucket["reasons"].get(result.reason, 0) + 1
        mode_bucket["latency_ms"].append(result.latency_ms)
        scenario_bucket["attempts"] += 1
        scenario_bucket["passes_by_mode"][result.mode] = (
            scenario_bucket["passes_by_mode"].get(result.mode, 0) + int(result.passed)
        )
        scenario_bucket["reasons_by_mode"].setdefault(result.mode, {})
        scenario_bucket["reasons_by_mode"][result.mode][result.reason] = (
            scenario_bucket["reasons_by_mode"][result.mode].get(result.reason, 0) + 1
        )
    for bucket in by_mode.values():
        attempts = bucket["attempts"]
        unauthorized_attempts = bucket["unauthorized_attempts"]
        values = sorted(bucket.pop("latency_ms"))
        bucket["pass_rate"] = bucket["passes"] / attempts if attempts else 0.0
        bucket["unauthorized_pass_rate"] = (
            bucket["unauthorized_passes"] / unauthorized_attempts if unauthorized_attempts else 0.0
        )
        bucket["latency_ms"] = _summary(values)
    return {"by_mode": by_mode, "by_scenario": by_scenario}


def _sender_signature_gate(
    mode: str,
    scenario: str,
    gateway: Gateway,
    sender_id: str,
    message: FrozenMessage,
    old_message: FrozenMessage,
    profile: ScenarioProfile,
    started: float,
    unauthorized: bool,
) -> BaselineResult:
    registration = gateway.registry.get(sender_id)
    if registration is None:
        return _result(mode, scenario, False, "unregistered_sender", started, unauthorized)
    expected_payload = _message_signature_payload(message)
    signed_message = old_message if not profile.valid_message_binding else message
    signed_payload = _message_signature_payload(signed_message)
    signing_key = (
        gateway.sidecars[sender_id].signing_key
        if profile.valid_sender_signature
        else SigningKey(hash_bytes("baseline-fake-sender-key", sender_id)[:32])
    )
    signature = sign_payload(signing_key, signed_payload)
    if not verify_payload(registration.verify_key, expected_payload, signature):
        reason = "wrong_message_hash" if not profile.valid_message_binding else "wrong_signature"
        return _result(mode, scenario, False, reason, started, unauthorized)
    return _result(mode, scenario, True, "valid_sender_signature", started, unauthorized)


def _unanimous_signature_gate(
    mode: str,
    scenario: str,
    gateway: Gateway,
    message: FrozenMessage,
    old_message: FrozenMessage,
    profile: ScenarioProfile,
    started: float,
    unauthorized: bool,
) -> BaselineResult:
    if not profile.registered_sender:
        return _result(mode, scenario, False, "unregistered_sender", started, unauthorized)
    expected_payload = _unanimous_signature_payload(message)
    signed_message = old_message if not profile.valid_message_binding else message
    signed_payload = _unanimous_signature_payload(signed_message)
    for index, agent_id in enumerate(gateway.registry.original_agent_ids):
        if profile.valid_unanimous_signatures:
            signing_key = gateway.sidecars[agent_id].signing_key
        else:
            signing_key = SigningKey(hash_bytes("baseline-fake-unanimous-key", agent_id, index)[:32])
        signature = sign_payload(signing_key, signed_payload)
        registration = gateway.registry.require(agent_id)
        if not verify_payload(registration.verify_key, expected_payload, signature):
            reason = "wrong_message_hash" if not profile.valid_message_binding else "missing_valid_signature"
            return _result(mode, scenario, False, reason, started, unauthorized)
    return _result(mode, scenario, True, "all_registered_agents_signed", started, unauthorized)


def _message_signature_payload(message: FrozenMessage) -> dict[str, str]:
    return {
        "message_id": message.message_id,
        "sender_id": message.sender_id,
        "receiver_id": message.receiver_id,
        "epoch": message.epoch,
    }


def _unanimous_signature_payload(message: FrozenMessage) -> dict[str, str]:
    return {
        "message_id": message.message_id,
        "sender_id": message.sender_id,
        "receiver_id": message.receiver_id,
        "epoch": message.epoch,
        "gate": "unanimous_signature",
    }


def _canonical_scenario(scenario: str) -> str:
    for suffix in ("_early", "_middle", "_late"):
        if scenario.endswith(suffix):
            return scenario[: -len(suffix)]
    return scenario


def _result(
    mode: str,
    scenario: str,
    passed: bool,
    reason: str,
    started: float,
    unauthorized: bool,
) -> BaselineResult:
    return BaselineResult(
        mode=mode,
        scenario=scenario,
        passed=passed,
        reason=reason,
        latency_ms=(time.perf_counter() - started) * 1000.0,
        unauthorized=unauthorized,
    )


def _summary(values: list[float]) -> dict[str, float]:
    if not values:
        return {"p50": 0.0, "p95": 0.0, "p99": 0.0, "max": 0.0}
    return {
        "p50": values[len(values) // 2],
        "p95": _percentile(values, 0.95),
        "p99": _percentile(values, 0.99),
        "max": values[-1],
    }


def _percentile(values: list[float], percentile: float) -> float:
    return values[min(len(values) - 1, math.ceil(percentile * len(values)) - 1)]
