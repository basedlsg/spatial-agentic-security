"""Compare random_plus / old-spatial / anti-leak-spatial under partial compromise.

Main metric: the target's residual (and one-shot success = 1/residual) at access levels
A0 (public only), A2 (one stolen neighbor), A3 (two stolen neighbors), A4 (one stolen
non-target sidecar == one neighbor in residual terms), A7 (solver near-miss == A0 residual).
Milestone: anti-leak A2/A3 residual higher than the old generator. Random is the ceiling
(independent factor: residual unchanged by stolen neighbors); approaching it is the stretch.
No outcome is favored.
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
from spatial_swarm.spatial_puzzle.experiments import anti_leak, pcs_metrics

TIERS = {
    "n4k4": {"n": 4, "k": 4, "trials": 20, "pool": 60, "budget": (5.0, 2_000_000)},
    "n5k4": {"n": 5, "k": 4, "trials": 20, "pool": 60, "budget": (8.0, 3_000_000)},
}
# anti-leak thresholds for the yield metric (from the n=5,k=4 probe: ~p75 A2, ~p90 A3)
_THRESHOLDS = {"n4k4": (15, 6), "n5k4": (30, 10)}


def _levels_from_score(c: anti_leak.CandidateScore) -> dict:
    """Residual per access level for one selected puzzle (A4==A2 worst; A7==A0)."""

    return {
        "A0_public_only": c.a0,
        "A2_one_stolen_neighbor": c.worst_a2,
        "A3_two_stolen_neighbors": c.worst_a3,
        "A4_one_stolen_sidecar_non_target": c.worst_a2,
        "A7_solver_generated_near_miss": c.a0,
    }


def _one_shot(residual: Optional[int]) -> Optional[float]:
    return (1.0 / residual) if residual else None


def run_tier(tier: str, *, trials: Optional[int] = None, pool: Optional[int] = None) -> dict:
    cfg = TIERS[tier]
    n, k, budget = cfg["n"], cfg["k"], cfg["budget"]
    ntrials = trials or cfg["trials"]
    npool = pool or cfg["pool"]
    levels = ["A0_public_only", "A2_one_stolen_neighbor", "A3_two_stolen_neighbors",
              "A4_one_stolen_sidecar_non_target", "A7_solver_generated_near_miss"]

    old_resid = {lv: [] for lv in levels}
    anti_resid = {lv: [] for lv in levels}
    rand_bits = []
    yields = []
    paired = {lv: {"anti_gt_old": 0, "anti_ge_old": 0, "n": 0} for lv in levels}
    pool_a0_acceptable = []

    for t in range(ntrials):
        rng = random.Random(70_000 + t)
        scored = anti_leak.generate_pool(rng, n=n, k=k, pool=npool, budget=budget,
                                         seed_base=70_000 + t * 1000)
        old = anti_leak.select_old(scored)
        anti = anti_leak.select_anti_leak(scored)
        if old is None or anti is None:
            continue
        pool_a0_acceptable.append(sum(1 for c in scored if c.a0_ok))
        ta2, ta3 = _THRESHOLDS[tier]
        yields.append(anti_leak.threshold_yield(scored, target_a2=ta2, target_a3=ta3))
        if anti.a0:
            rand_bits.append(anti_leak.matched_random_bits(anti.a0))
        ol, al = _levels_from_score(old), _levels_from_score(anti)
        for lv in levels:
            if ol[lv] is not None:
                old_resid[lv].append(float(ol[lv]))
            if al[lv] is not None:
                anti_resid[lv].append(float(al[lv]))
            if ol[lv] is not None and al[lv] is not None:
                paired[lv]["n"] += 1
                paired[lv]["anti_gt_old"] += int(al[lv] > ol[lv])
                paired[lv]["anti_ge_old"] += int(al[lv] >= ol[lv])

    def _summ(vals):
        return {"median": statistics.median(vals), "summary": _latency_summary(vals),
                "one_shot_median": _one_shot(int(round(statistics.median(vals))))} if vals else None

    rb = statistics.median(rand_bits) if rand_bits else None
    return {
        "config": {"tier": tier, "n": n, "k": k, "trials": ntrials, "pool": npool,
                   "budget_seconds": budget[0]},
        "thresholds_a2_a3": _THRESHOLDS[tier],
        "anti_leak_threshold_yield": pcs_metrics.proportion(
            sum(1 for y in yields if y > 0), len(yields)) if yields else None,
        "anti_leak_threshold_yield_mean": statistics.mean(yields) if yields else None,
        "median_pool_a0_acceptable": statistics.median(pool_a0_acceptable) if pool_a0_acceptable else None,
        "random_plus": {
            "matched_bits_median": rb,
            "one_shot_success": (2.0 ** (-rb)) if rb else None,
            "note": "independent random factor: residual constant under stolen neighbors",
        },
        "residual_by_level": {
            lv: {"old_spatial": _summ(old_resid[lv]), "anti_leak_spatial": _summ(anti_resid[lv])}
            for lv in levels
        },
        "paired_anti_vs_old": {
            lv: {
                "n": paired[lv]["n"],
                "anti_strictly_higher": pcs_metrics.proportion(paired[lv]["anti_gt_old"], paired[lv]["n"]) if paired[lv]["n"] else None,
                "anti_at_least_old": pcs_metrics.proportion(paired[lv]["anti_ge_old"], paired[lv]["n"]) if paired[lv]["n"] else None,
            }
            for lv in levels
        },
    }


def _summary_md(metrics: dict) -> str:
    lines = ["# Anti-leak spatial generator summary", "",
             f"- positive_controls.valid: {metrics['positive_controls']['valid']}",
             f"- redaction.clean: {metrics.get('redaction', {}).get('clean')}"]
    for tier, t in metrics["tiers"].items():
        rl = t["residual_by_level"]
        for lv in ("A2_one_stolen_neighbor", "A3_two_stolen_neighbors"):
            old = rl[lv]["old_spatial"]
            anti = rl[lv]["anti_leak_spatial"]
            om = old["median"] if old else None
            am = anti["median"] if anti else None
            lines.append(f"- [{tier}] {lv}: old median={om} anti-leak median={am}")
    return "\n".join(lines) + "\n"


def main(argv: Optional[list] = None) -> Path:
    parser = argparse.ArgumentParser(description="Anti-leak spatial generator comparison.")
    parser.add_argument("--tier", default="n5k4", choices=["n4k4", "n5k4", "both"])
    parser.add_argument("--trials", type=int, default=None)
    parser.add_argument("--pool", type=int, default=None)
    parser.add_argument("--output-root", default="runs")
    args = parser.parse_args(argv)

    tiers = ["n4k4", "n5k4"] if args.tier == "both" else [args.tier]
    run_dir = Path(args.output_root) / utc_run_id()
    run_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as ctmp:
        controls = pcs_metrics.positive_controls(n=3, k=4, tmp_dir=Path(ctmp))

    tier_results = {t: run_tier(t, trials=args.trials, pool=args.pool) for t in tiers}
    metrics = {
        "experiment": "spatial_anti_leak_generator",
        "positive_controls": controls,
        "tiers": tier_results,
    }

    config = {"experiment": "anti_leak_generator", "tiers": tiers,
              "trials_override": args.trials, "pool_override": args.pool,
              "secret_material_redacted": True}
    write_yaml_like(run_dir / "config.yaml", config)
    write_environment(run_dir)
    write_git_commit(run_dir)

    full = dict(metrics)
    full["run_config"] = config
    full["resource_use"] = process_resource_use()
    write_metrics_and_digest(run_dir / "metrics.json", full)
    write_metrics(run_dir / "confidence_intervals.json",
                  {t: r["paired_anti_vs_old"] for t, r in tier_results.items()})
    write_metrics(run_dir / "run_manifest.json", {
        "experiment": metrics["experiment"], "run_id": run_dir.name,
        "tiers": tiers, "positive_controls_valid": controls["valid"],
        "artifacts": sorted(p.name for p in run_dir.iterdir() if p.is_file()),
    })
    (run_dir / "summary.md").write_text(_summary_md({**metrics, "tiers": tier_results}), encoding="utf-8")
    write_metrics(run_dir / "redaction.json", pcs_metrics.scan_for_secrets(run_dir))

    print(run_dir)
    return run_dir


if __name__ == "__main__":
    main()
