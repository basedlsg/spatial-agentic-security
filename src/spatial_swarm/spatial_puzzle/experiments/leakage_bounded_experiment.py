"""Does a sparse-placement construction bound the neighbor-theft leak better than dense?

Compares the dense generator (pieces tile the target, rho=1) against the leakage-bounded
sparse construction at several sparsity ratios rho = |ambient|/(n*k), paired by seed. The
headline metric is bits lost from A0 to A3 (log2(residual_A0 / residual_A3)) -- a
scale-free measure of how much stolen neighbors prune the target. A matched random factor
loses 0 bits; the dense generator loses many; the question is how far sparse closes that.

The anti-leak SELECTION result (docs/findings_spatial_anti_leak_generator.md) is the
intermediate reference and is not recomputed here.
"""

from __future__ import annotations

import argparse
import random
import statistics
import tempfile
from pathlib import Path
from typing import Optional

from spatial_swarm.experiments.metrics import (
    _latency_summary,
    process_resource_use,
    write_metrics,
    write_metrics_and_digest,
)
from spatial_swarm.experiments.report import (
    utc_run_id,
    write_environment,
    write_git_commit,
    write_yaml_like,
)
from spatial_swarm.spatial_puzzle.experiments import leakage_bounded as LB
from spatial_swarm.spatial_puzzle.experiments import pcs_metrics
from spatial_swarm.spatial_puzzle.generators.build import build_hidden_solution

TIERS = {
    "n3k4": {"n": 3, "k": 4, "ambient_sweep": [18, 24, 30, 36], "trials": 20, "budget": (10.0, 4_000_000)},
    "n4k4": {"n": 4, "k": 4, "ambient_sweep": [24, 32, 40], "trials": 20, "budget": (10.0, 4_000_000)},
}


def _med(x):
    return statistics.median(x) if x else None


def _one_shot(residual):
    return (1.0 / residual) if residual else None


def run_tier(tier: str, *, trials: Optional[int] = None) -> dict:
    cfg = TIERS[tier]
    n, k, budget = cfg["n"], cfg["k"], cfg["budget"]
    ntrials = trials or cfg["trials"]
    sweep = cfg["ambient_sweep"]

    dense = {"a0": [], "a3": [], "lost_a2": [], "lost_a3": []}
    sparse = {amb: {"a0": [], "a3": [], "lost_a2": [], "lost_a3": [], "ambient": [],
                    "beats_dense_a3": 0, "paired": 0} for amb in sweep}
    gen_failures = 0

    for t in range(ntrials):
        seed = 40_000 + t
        d = LB.leak_profile(build_hidden_solution(random.Random(seed), n=n, k=k, swarm_id=f"dense-{seed}"),
                            budget=budget)
        if not d["enumerated"]:
            continue
        dense["a0"].append(float(d["a0"]))
        dense["a3"].append(float(d["worst_a3"]))
        if d["bits_lost_a0_to_a2"] is not None:
            dense["lost_a2"].append(d["bits_lost_a0_to_a2"])
        if d["bits_lost_a0_to_a3"] is not None:
            dense["lost_a3"].append(d["bits_lost_a0_to_a3"])

        for amb in sweep:
            try:
                sol = LB.build_sparse_solution(random.Random(seed), n=n, k=k, ambient_size=amb,
                                              swarm_id=f"sparse-{amb}-{seed}")
            except RuntimeError:
                gen_failures += 1
                continue
            s = LB.leak_profile(sol, budget=budget)
            if not s["enumerated"]:
                continue
            sparse[amb]["a0"].append(float(s["a0"]))
            sparse[amb]["a3"].append(float(s["worst_a3"]))
            sparse[amb]["ambient"].append(len(sol.target))
            if s["bits_lost_a0_to_a2"] is not None:
                sparse[amb]["lost_a2"].append(s["bits_lost_a0_to_a2"])
            if s["bits_lost_a0_to_a3"] is not None:
                sparse[amb]["lost_a3"].append(s["bits_lost_a0_to_a3"])
            if d["bits_lost_a0_to_a3"] is not None and s["bits_lost_a0_to_a3"] is not None:
                sparse[amb]["paired"] += 1
                sparse[amb]["beats_dense_a3"] += int(s["bits_lost_a0_to_a3"] < d["bits_lost_a0_to_a3"])

    def _summary(block, is_sparse):
        a0m = _med(block["a0"])
        out = {
            "a0_residual_median": a0m,
            "a3_residual_median": _med(block["a3"]),
            "bits_lost_a0_to_a2_median": _med(block["lost_a2"]),
            "bits_lost_a0_to_a3_median": _med(block["lost_a3"]),
            "bits_lost_a0_to_a3_summary": _latency_summary(block["lost_a3"]) if block["lost_a3"] else None,
            "a3_one_shot_median": _one_shot(int(round(_med(block["a3"])))) if block["a3"] else None,
            "matched_random_one_shot": _one_shot(int(round(a0m))) if a0m else None,
        }
        if is_sparse:
            out["ambient_cells_median"] = _med(block["ambient"])
            out["sparsity_rho"] = (_med(block["ambient"]) / (n * k)) if block["ambient"] else None
            out["beats_dense_a3_leak"] = (pcs_metrics.proportion(block["beats_dense_a3"], block["paired"])
                                          if block["paired"] else None)
        return out

    return {
        "config": {"tier": tier, "n": n, "k": k, "trials": ntrials, "ambient_sweep": sweep,
                   "budget_seconds": budget[0]},
        "generation_failures": gen_failures,
        "dense": _summary(dense, is_sparse=False),
        "sparse_by_ambient": {str(amb): _summary(sparse[amb], is_sparse=True) for amb in sweep},
    }


def _summary_md(metrics: dict) -> str:
    lines = ["# Leakage-bounded construction summary", "",
             f"- positive_controls.valid: {metrics['positive_controls']['valid']}",
             f"- redaction.clean: {metrics.get('redaction', {}).get('clean')}"]
    for tier, t in metrics["tiers"].items():
        d = t["dense"]["bits_lost_a0_to_a3_median"]
        lines.append(f"- [{tier}] dense bits_lost A0->A3 median = {d}")
        for amb, s in t["sparse_by_ambient"].items():
            lines.append(f"    ambient={amb} rho={s['sparsity_rho']:.2f} bits_lost A0->A3 = {s['bits_lost_a0_to_a3_median']}"
                         f" (beats dense: {s['beats_dense_a3_leak']['rate'] if s.get('beats_dense_a3_leak') else None})")
    return "\n".join(lines) + "\n"


def main(argv: Optional[list] = None) -> Path:
    parser = argparse.ArgumentParser(description="Leakage-bounded sparse construction vs dense.")
    parser.add_argument("--tier", default="n3k4", choices=["n3k4", "n4k4", "both"])
    parser.add_argument("--trials", type=int, default=None)
    parser.add_argument("--output-root", default="runs")
    args = parser.parse_args(argv)

    tiers = ["n3k4", "n4k4"] if args.tier == "both" else [args.tier]
    run_dir = Path(args.output_root) / utc_run_id()
    run_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as ctmp:
        controls = pcs_metrics.positive_controls(n=3, k=4, tmp_dir=Path(ctmp))

    tier_results = {t: run_tier(t, trials=args.trials) for t in tiers}
    metrics = {"experiment": "spatial_leakage_bounded", "positive_controls": controls, "tiers": tier_results}

    config = {"experiment": "leakage_bounded", "tiers": tiers, "secret_material_redacted": True}
    write_yaml_like(run_dir / "config.yaml", config)
    write_environment(run_dir)
    write_git_commit(run_dir)

    full = dict(metrics)
    full["run_config"] = config
    full["resource_use"] = process_resource_use()
    write_metrics_and_digest(run_dir / "metrics.json", full)
    (run_dir / "summary.md").write_text(_summary_md({**metrics, "tiers": tier_results}), encoding="utf-8")
    write_metrics(run_dir / "redaction.json", pcs_metrics.scan_for_secrets(run_dir))

    print(run_dir)
    return run_dir


if __name__ == "__main__":
    main()
