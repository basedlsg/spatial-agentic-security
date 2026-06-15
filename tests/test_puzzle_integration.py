"""End-to-end spatial-puzzle run: artifacts, controls, bake-off, redaction."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from spatial_swarm.spatial_puzzle.experiments import cli


def test_all_experiments_run_and_produce_artifacts(tmp_path: Path):
    run_dir = cli.main(["--experiment", "all", "--n", "3", "--k", "4", "--seeds", "3", "--output-root", str(tmp_path)])
    for name in ("metrics.json", "metrics.json.sha256", "config.yaml", "environment.txt",
                 "git_commit.txt", "summary.md", "redaction.json"):
        assert (run_dir / name).exists(), name

    digest = (run_dir / "metrics.json.sha256").read_text(encoding="utf-8").strip()
    assert digest == hashlib.sha256((run_dir / "metrics.json").read_bytes()).hexdigest()

    m = json.loads((run_dir / "metrics.json").read_text(encoding="utf-8"))
    assert m["positive_controls"]["valid"] is True
    assert m["solver_bakeoff"]["all_agree_on_residual"] is True
    # leakage ladder present with a random ceiling
    assert m["leakage_ladder"]["random_ceiling"]["residual_median"] is not None
    # redaction clean (commitments are hashes; no coords/keys/seed in artifacts)
    assert json.loads((run_dir / "redaction.json").read_text())["clean"] is True


def test_single_experiment_solver_bakeoff(tmp_path: Path):
    run_dir = cli.main(["--experiment", "solver_bakeoff", "--n", "3", "--k", "4", "--output-root", str(tmp_path)])
    m = json.loads((run_dir / "metrics.json").read_text())
    assert "solver_bakeoff" in m and m["solver_bakeoff"]["all_agree_on_residual"] is True
