"""metrics.json carries an output-binding sha256 digest."""

from __future__ import annotations

import hashlib
from pathlib import Path

from spatial_swarm.experiments.runner import run_experiment


def test_metrics_digest_matches_file_bytes(tmp_path: Path):
    run_dir = run_experiment(
        scenario="honest",
        agent_count=4,
        fragment_size=8,
        attempts=3,
        seed=11,
        output_root=tmp_path,
    )
    metrics = run_dir / "metrics.json"
    digest_file = run_dir / "metrics.json.sha256"
    assert metrics.exists()
    assert digest_file.exists()
    expected = hashlib.sha256(metrics.read_bytes()).hexdigest()
    assert digest_file.read_text(encoding="utf-8").strip() == expected


def test_metrics_digest_written_for_forgery_matrix(tmp_path: Path):
    run_dir = run_experiment(
        scenario="ai_forgery_matrix",
        agent_count=4,
        fragment_size=8,
        attempts=1,
        seed=12,
        output_root=tmp_path,
    )
    digest_file = run_dir / "metrics.json.sha256"
    assert digest_file.exists()
    expected = hashlib.sha256((run_dir / "metrics.json").read_bytes()).hexdigest()
    assert digest_file.read_text(encoding="utf-8").strip() == expected
