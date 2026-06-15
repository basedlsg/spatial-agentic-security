"""End-to-end run: artifacts, gating controls, CIs, redaction."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from spatial_swarm.spatial_lab import run as Run


def test_exact_run_produces_valid_artifacts(tmp_path: Path):
    run_dir = Run.main(
        ["--tier", "exact", "--reprs", "R0,R2,R4", "--lab", "both", "--seeds", "3",
         "--output-root", str(tmp_path)]
    )
    # artifacts exist
    for name in ("metrics.json", "metrics.json.sha256", "config.yaml", "environment.txt",
                 "git_commit.txt", "summary.md", "redaction.json"):
        assert (run_dir / name).exists(), name

    # digest binds the metrics bytes
    digest = (run_dir / "metrics.json.sha256").read_text(encoding="utf-8").strip()
    assert digest == hashlib.sha256((run_dir / "metrics.json").read_bytes()).hexdigest()

    metrics = json.loads((run_dir / "metrics.json").read_text(encoding="utf-8"))
    # positive controls gate the run
    assert metrics["positive_controls"]["valid"] is True
    # confidence intervals present on a success cell
    cell = metrics["lab_A_registration"]["exact"]["R2"]["registration_exhaustive"]
    assert set(cell["found_rate_ci95"]) == {"low", "high"}
    # Lab B observation curve present
    assert "exact" in metrics["observation_curves"]
    # redaction clean
    assert json.loads((run_dir / "redaction.json").read_text())["clean"] is True
    # llm not run (no provider)
    assert metrics["llm_attacker"]["status"] == "not_run"


def _strip_timing(obj):
    """Recursively drop wall-clock fields so only deterministic results remain."""

    if isinstance(obj, dict):
        return {k: _strip_timing(v) for k, v in obj.items() if k != "wall_seconds"}
    if isinstance(obj, list):
        return [_strip_timing(v) for v in obj]
    return obj


def test_run_is_deterministic_modulo_timestamps(tmp_path: Path):
    a = Run.main(["--tier", "exact", "--reprs", "R0,R2", "--lab", "A", "--seeds", "3", "--output-root", str(tmp_path / "a")])
    b = Run.main(["--tier", "exact", "--reprs", "R0,R2", "--lab", "A", "--seeds", "3", "--output-root", str(tmp_path / "b")])
    ma = json.loads((a / "metrics.json").read_text())
    mb = json.loads((b / "metrics.json").read_text())
    # deterministic fields (found counts, nodes, candidate counts) must match;
    # wall_seconds and resource_use are timing-dependent and excluded.
    assert _strip_timing(ma["lab_A_registration"]) == _strip_timing(mb["lab_A_registration"])
