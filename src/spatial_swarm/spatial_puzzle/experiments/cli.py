"""CLI for the spatial-puzzle experiments; writes run artifacts (mirrors spatial_lab/run.py)."""

from __future__ import annotations

import argparse
from pathlib import Path
from typing import Optional

from spatial_swarm.crypto.hashing import sha256_hex
from spatial_swarm.experiments.metrics import (
    process_resource_use,
    write_metrics,
    write_metrics_and_digest,
)
from spatial_swarm.experiments.redaction import redaction_report
from spatial_swarm.experiments.report import (
    utc_run_id,
    write_environment,
    write_git_commit,
    write_yaml_like,
)
from spatial_swarm.spatial_puzzle.experiments import orchestrate

_EXPERIMENTS = {
    "adversarial_generation": lambda a: orchestrate.run_adversarial_generation(n=a.n, k=a.k, seeds=a.seeds),
    "leakage_ladder": lambda a: orchestrate.run_leakage_ladder(n=a.n, k=a.k, seeds=a.seeds),
    "one_shot_vs_retry": lambda a: orchestrate.run_one_shot_vs_retry(n=a.n, k=a.k, seeds=a.seeds),
    "partial_compromise": lambda a: orchestrate.run_partial_compromise(n=a.n, k=a.k, seeds=a.seeds),
    "solver_bakeoff": lambda a: orchestrate.run_solver_bakeoff(n=a.n, k=a.k),
    "detector_keystone": lambda a: orchestrate.run_detector_keystone(n=a.n, k=a.k, seeds=a.seeds),
}


def _summary_md(metrics: dict) -> str:
    lines = ["# Spatial-puzzle experiment summary", ""]
    pc = metrics.get("positive_controls")
    if pc:
        lines.append(f"- positive_controls.valid: {pc['valid']}")
    osr = metrics.get("one_shot_vs_retry", {})
    if "random_ceiling" in osr and "spatial_post_clue" in osr:
        lines.append(
            f"- one-shot recovery: random ceiling {osr['random_ceiling']['analytic_recovery_prob']:.4f} "
            f"vs spatial post-clue {osr['spatial_post_clue']['analytic_recovery_prob']:.4f}"
        )
    bake = metrics.get("solver_bakeoff", {})
    if bake:
        lines.append(f"- solver bakeoff agree_on_residual: {bake.get('all_agree_on_residual')} residual={bake.get('residual')}")
    det = metrics.get("detector_keystone", {})
    if det:
        roll = det.get("rollup", {})
        dpc = det.get("positive_controls", {})
        lines.append(f"- detector positive_controls.valid: {dpc.get('valid')}")
        lines.append(
            f"- geometry marginal detection advantage: {roll.get('geometry_marginal_detection_advantage_count')}"
            f" | marginal leakage bits: {roll.get('geometry_marginal_leakage_bits')}"
            f" | false-positive delta: {roll.get('false_positive_delta')}"
        )
    return "\n".join(lines) + "\n"


def main(argv: Optional[list[str]] = None) -> Path:
    parser = argparse.ArgumentParser(description="Run spatial-puzzle experiments.")
    parser.add_argument("--experiment", default="all", choices=["all", *_EXPERIMENTS])
    parser.add_argument("--n", type=int, default=3)
    parser.add_argument("--k", type=int, default=4)
    parser.add_argument("--seeds", type=int, default=12)
    parser.add_argument("--output-root", default="runs")
    args = parser.parse_args(argv)

    if args.experiment == "all":
        metrics = orchestrate.run_all(n=args.n, k=args.k, seeds=args.seeds)
    else:
        metrics = {"config": {"n": args.n, "k": args.k, "seeds": args.seeds},
                   args.experiment: _EXPERIMENTS[args.experiment](args)}

    run_dir = Path(args.output_root) / utc_run_id()
    run_dir.mkdir(parents=True, exist_ok=True)
    config = {
        "experiment": f"spatial_puzzle:{args.experiment}",
        "n": args.n, "k": args.k, "seeds": args.seeds,
        "determinism_commitment": sha256_hex({"kind": "spatial_puzzle_seed", "n": args.n, "k": args.k}),
        "secret_material_redacted": True,
    }
    write_yaml_like(run_dir / "config.yaml", config)
    write_environment(run_dir)
    write_git_commit(run_dir)

    full = dict(metrics)
    full["run_config"] = config
    full["resource_use"] = process_resource_use()
    write_metrics_and_digest(run_dir / "metrics.json", full)
    (run_dir / "summary.md").write_text(_summary_md(metrics), encoding="utf-8")
    write_metrics(run_dir / "redaction.json", redaction_report(run_dir))

    print(run_dir)
    return run_dir


if __name__ == "__main__":
    main()
