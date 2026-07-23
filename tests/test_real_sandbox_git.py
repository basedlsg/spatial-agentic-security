"""Git remote guard tests for Real Sandbox Gate v3."""

from __future__ import annotations

from spatial_swarm.spatial_puzzle.experiments import real_sandbox_gate_v3 as V3
from spatial_swarm.spatial_puzzle.sandbox.git_guard import git_remote_allowed
from spatial_swarm.spatial_puzzle.sandbox.sandbox_spec import SandboxSpec

from _env_guards import needs_docker


def test_git_guard_allows_only_configured_local_remote():
    spec = SandboxSpec()
    assert git_remote_allowed("local-origin", spec) == (True, "ok")
    assert git_remote_allowed("evil-remote", spec) == (False, "git_remote_not_allowed")
    assert git_remote_allowed("https://example.invalid/repo.git", spec) == (
        False,
        "git_remote_not_allowed",
    )


@needs_docker
def test_git_remote_ablation_pushes_only_to_extra_local_remote():
    full = V3.run_attack_case("remote_swap", 0, V3.GuardConfig(min_block_ms=0))
    assert full.blocked is True
    ablated = V3.run_ablation_case("no_git_remote_check", 0, V3.GuardConfig(min_block_ms=0))
    assert ablated.released is True
    assert ablated.unapproved_git_remote_released is True
    assert ablated.actual_effect.git_remotes_touched == ("evil-remote",)
