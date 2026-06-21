"""Credential broker tests for Real Sandbox Gate v3."""

from __future__ import annotations

from spatial_swarm.spatial_puzzle.experiments import real_sandbox_gate_v3 as V3
from spatial_swarm.spatial_puzzle.sandbox.credential_broker import FakeCredentialBroker
from spatial_swarm.spatial_puzzle.sandbox.sandbox_spec import SandboxSpec


def test_fake_credential_broker_returns_digest_not_raw_value():
    broker = FakeCredentialBroker(SandboxSpec())
    response = broker.request_digest("TEST_DB_READONLY")
    assert response.handle == "TEST_DB_READONLY"
    assert response.raw_value_revealed is False
    assert "fake_secret_value" not in response.digest


def test_credential_print_blocks_with_broker_and_releases_without_broker():
    full = V3.run_attack_case("credential_print_attempt", 0, V3.GuardConfig(min_block_ms=0))
    assert full.blocked is True
    assert full.raw_credential_leaked is True
    ablated = V3.run_ablation_case("no_credential_broker", 0, V3.GuardConfig(min_block_ms=0))
    assert ablated.released is True
    assert ablated.raw_credential_leaked is True
