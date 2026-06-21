"""Real sandbox adapter integration tests."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from spatial_swarm.spatial_puzzle.experiments import real_sandbox_gate_v3 as V3
from spatial_swarm.spatial_puzzle.sandbox import ContainerAdapter


def _envelope(raw: V3.RawAction, guard: V3.GuardConfig = V3.GuardConfig()):
    with tempfile.TemporaryDirectory(prefix="v3-test-env-") as tmp:
        repo = ContainerAdapter(guard.spec_for(raw)).create_repo_template(Path(tmp))
        return V3.ActionCanonicalizerV3(repo, guard=guard, raw=raw).envelope(nonce_label="test")


def test_adapter_runs_allowlisted_command_inside_docker():
    raw = V3._default_raw("run_command")
    env = _envelope(raw)
    result = ContainerAdapter(V3.GuardConfig().spec_for(raw)).execute(env)
    assert result.blocked is False
    assert result.effect_violation is False
    assert result.actual_effects.commands_run == ("safe_format",)
    assert result.actual_effects.subprocesses_spawned == 1
    assert result.actual_effects.working_directory_used == "/workspace/repo"


def test_tiny_cli_run_writes_required_artifacts(tmp_path: Path):
    run_dir = V3.main(
        [
            "--mode",
            "quick",
            "--valid-trials",
            "0",
            "--attack-trials",
            "0",
            "--ablation-trials",
            "0",
            "--transaction-trials",
            "0",
            "--constant-failure-trials",
            "0",
            "--min-block-ms",
            "0",
            "--output-root",
            str(tmp_path),
        ]
    )
    required = {
        "metrics.json",
        "metrics.json.sha256",
        "sandbox_config.json",
        "valid_action_results.csv",
        "attack_matrix.csv",
        "effect_records.jsonl",
        "ablation_results.csv",
        "transaction_results.csv",
        "constant_failure_results.csv",
        "redaction.json",
        "run_environment.json",
        "git_commit.txt",
    }
    assert required.issubset({path.name for path in run_dir.iterdir()})
    redaction = json.loads((run_dir / "redaction.json").read_text(encoding="utf-8"))
    assert redaction["clean"] is True
