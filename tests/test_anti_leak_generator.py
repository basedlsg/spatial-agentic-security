"""Anti-leak spatial generator: scoring monotonicity, selection, artifacts, redaction."""

from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path

from spatial_swarm.spatial_puzzle.experiments import anti_leak
from spatial_swarm.spatial_puzzle.experiments import anti_leak_experiment as E


def test_score_monotonic_under_more_stolen_neighbors():
    rng = random.Random(70_000)
    pool = anti_leak.generate_pool(rng, n=5, k=4, pool=8, budget=(8.0, 3_000_000), seed_base=70_000)
    enumerated = [c for c in pool if c.enumerated]
    assert enumerated, "expected at least one enumerable candidate"
    for c in enumerated:
        # revealing more neighbors shrinks the region -> worst-case residual cannot grow
        assert c.a0 >= c.worst_a2 >= c.worst_a3


def test_anti_leak_selection_maximizes_bottleneck():
    rng = random.Random(70_500)
    pool = anti_leak.generate_pool(rng, n=5, k=4, pool=20, budget=(8.0, 3_000_000), seed_base=70_500)
    anti = anti_leak.select_anti_leak(pool)
    assert anti is not None
    acceptable = [c for c in pool if c.a0_ok] or [c for c in pool if c.enumerated]
    # the anti-leak pick has the maximum bottleneck score over the candidate set
    assert anti.anti_leak_score == max(c.anti_leak_score for c in acceptable)


def test_old_vs_anti_leak_anti_is_not_worse_on_bottleneck():
    rng = random.Random(71_000)
    pool = anti_leak.generate_pool(rng, n=5, k=4, pool=20, budget=(8.0, 3_000_000), seed_base=71_000)
    old = anti_leak.select_old(pool)
    anti = anti_leak.select_anti_leak(pool)
    assert old is not None and anti is not None
    assert anti.anti_leak_score >= old.anti_leak_score  # selection never reduces the bottleneck


def test_end_to_end_run_artifacts_and_redaction(tmp_path: Path):
    run_dir = E.main(["--tier", "n5k4", "--trials", "4", "--pool", "16", "--output-root", str(tmp_path)])
    for name in ("metrics.json", "metrics.json.sha256", "config.yaml", "environment.txt",
                 "git_commit.txt", "confidence_intervals.json", "run_manifest.json",
                 "summary.md", "redaction.json"):
        assert (run_dir / name).exists(), name
    digest = (run_dir / "metrics.json.sha256").read_text().strip()
    assert digest == hashlib.sha256((run_dir / "metrics.json").read_bytes()).hexdigest()
    m = json.loads((run_dir / "metrics.json").read_text())
    assert m["positive_controls"]["valid"] is True
    assert json.loads((run_dir / "redaction.json").read_text())["clean"] is True
