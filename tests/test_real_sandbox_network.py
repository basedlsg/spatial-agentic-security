"""Network isolation tests for Real Sandbox Gate v3."""

from __future__ import annotations

import pytest

from spatial_swarm.spatial_puzzle.experiments import real_sandbox_gate_v3 as V3
from spatial_swarm.spatial_puzzle.sandbox.network_guard import (
    command_attempts_network,
    docker_network_args,
)

# The cases that actually execute containers need a working Docker backend + image.
_needs_docker = pytest.mark.skipif(
    not V3._docker_info().get("available", False),
    reason="requires a working Docker sandbox backend + container image",
)


def test_network_guard_defaults_to_docker_network_none():
    assert docker_network_args("off") == ("--network", "none")
    assert command_attempts_network(("curl", "https://example.invalid")) is True
    assert command_attempts_network(("python", "scripts/safe_format.py")) is False


@_needs_docker
def test_network_attacks_block_and_network_ablation_exposes_untraced_network():
    full = V3.run_attack_case("python_socket_attempt", 0, V3.GuardConfig(min_block_ms=0))
    assert full.blocked is True
    ablated = V3.run_ablation_case("no_network_isolation", 0, V3.GuardConfig(min_block_ms=0))
    assert ablated.released is True
    assert ablated.unapproved_network_released is True
