"""Command allowlist tests for Real Sandbox Gate v3."""

from __future__ import annotations

from spatial_swarm.spatial_puzzle.experiments import real_sandbox_gate_v3 as V3
from spatial_swarm.spatial_puzzle.sandbox.command_policy import evaluate_command
from spatial_swarm.spatial_puzzle.sandbox.sandbox_spec import SandboxSpec


def test_command_policy_accepts_only_exact_argv():
    spec = SandboxSpec()
    assert evaluate_command(("python", "scripts/safe_format.py"), spec).allowed is True
    assert evaluate_command(("python", "-c", "print('bad')"), spec).allowed is False
    assert evaluate_command(("bash", "-c", "echo bad"), spec).allowed is False
    assert evaluate_command(("python", "x.py;", "cat", ".env"), spec).reason == "command_injection"


def test_full_gate_blocks_shell_command_but_no_allowlist_releases():
    full = V3.run_attack_case("bash_c", 0, V3.GuardConfig(min_block_ms=0))
    assert full.blocked is True
    assert full.contained_started is False
    ablated = V3.run_ablation_case("no_command_allowlist", 0, V3.GuardConfig(min_block_ms=0))
    assert ablated.released is True
    assert ablated.command_injection_released is True
