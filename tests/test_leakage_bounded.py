"""Leakage-bounded construction: region/placement validity, leak reduction, artifacts."""

from __future__ import annotations

import hashlib
import json
import random
import statistics
from pathlib import Path

from spatial_swarm.spatial_lab import commit as C
from spatial_swarm.spatial_lab.shapes import is_connected
from spatial_swarm.spatial_puzzle.experiments import leakage_bounded as LB
from spatial_swarm.spatial_puzzle.experiments import leakage_bounded_experiment as E


def test_grow_region_connected_and_sized():
    r = LB.grow_region(random.Random(1), 20)
    assert len(r) == 20 and is_connected(r)


def test_place_spread_pieces_disjoint_connected():
    region = LB.grow_region(random.Random(2), 24)
    pieces = LB.place_spread_pieces(random.Random(2), region, n=3, k=4)
    assert pieces is not None and len(pieces) == 3
    seen = set()
    for p in pieces.values():
        assert len(p) == 4 and is_connected(p) and p <= region
        assert not (p & seen)   # disjoint
        seen |= p


def test_sparse_solution_commitments_open():
    sol = LB.build_sparse_solution(random.Random(3), n=3, k=4, ambient_size=24, swarm_id="t")
    assert len(sol.target) == 24
    for aid, piece in sol.pieces.items():
        assert piece <= sol.target
        assert C.opens(sol.commitments[aid], sol.swarm_id, aid, sol.repr_name, piece)


def test_sparse_reduces_neighbor_theft_leak_vs_dense():
    from spatial_swarm.spatial_puzzle.generators.build import build_hidden_solution
    dense_lost, sparse_lost = [], []
    for s in range(40_000, 40_006):
        d = LB.leak_profile(build_hidden_solution(random.Random(s), n=3, k=4, swarm_id=f"d{s}"),
                            budget=(6.0, 2_000_000))
        sp = LB.leak_profile(LB.build_sparse_solution(random.Random(s), n=3, k=4, ambient_size=30, swarm_id=f"s{s}"),
                             budget=(6.0, 2_000_000))
        if d["bits_lost_a0_to_a3"] is not None:
            dense_lost.append(d["bits_lost_a0_to_a3"])
        if sp["bits_lost_a0_to_a3"] is not None:
            sparse_lost.append(sp["bits_lost_a0_to_a3"])
    # the sparse construction loses fewer bits to two-neighbor theft than the dense generator
    assert statistics.median(sparse_lost) < statistics.median(dense_lost)


def test_end_to_end_run_artifacts(tmp_path: Path):
    run_dir = E.main(["--tier", "n3k4", "--trials", "3", "--output-root", str(tmp_path)])
    for name in ("metrics.json", "metrics.json.sha256", "config.yaml", "environment.txt",
                 "git_commit.txt", "summary.md", "redaction.json"):
        assert (run_dir / name).exists(), name
    digest = (run_dir / "metrics.json.sha256").read_text().strip()
    assert digest == hashlib.sha256((run_dir / "metrics.json").read_bytes()).hexdigest()
    m = json.loads((run_dir / "metrics.json").read_text())
    assert m["positive_controls"]["valid"] is True
    assert json.loads((run_dir / "redaction.json").read_text())["clean"] is True
