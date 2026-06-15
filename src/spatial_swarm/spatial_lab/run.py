"""CLI for the spatial-hardness experiment; writes run artifacts.

Mirrors experiments/runner.py: a timestamped run dir with config.yaml,
environment.txt, git_commit.txt, metrics.json (+ .sha256), summary.md, and a
redaction.json written last so it never scans itself.
"""

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
from spatial_swarm.spatial_lab.experiment import run_experiment


def _summary_md(metrics: dict) -> str:
    lines = ["# Spatial-hardness run summary", ""]
    lines.append(f"- positive_controls.valid: {metrics['positive_controls']['valid']}")
    for tier, posevs in metrics.get("pose_space_vs_random_bruteforce", {}).items():
        lines.append(f"\n## Lab A pose space vs random brute force ({tier})")
        for r, v in posevs.items():
            lines.append(
                f"- {r}: pose_space_bits={v['pose_space_bits']:.1f} "
                f"random_commitment_bits={v['random_commitment_bits']:.1f} "
                f"observation_saves_bits={v['observation_saves_bits']:.1f}"
            )
    for tier, labb in metrics.get("lab_B_assembly", {}).items():
        lines.append(f"\n## Lab B assembly found-rate ({tier})")
        for r, v in labb.items():
            if "assembly_backtrack" in v:
                a = v["assembly_backtrack"]
                lines.append(f"- {r}: found {a['found']}/{a['trials']}")
    return "\n".join(lines) + "\n"


def main(argv: Optional[list[str]] = None) -> Path:
    parser = argparse.ArgumentParser(description="Run the spatial-hardness experiment.")
    parser.add_argument("--tier", default="exact", choices=["exact", "scaling", "both"])
    parser.add_argument("--reprs", default="R0,R1,R2,R3,R4")
    parser.add_argument("--lab", default="both", choices=["A", "B", "both"])
    parser.add_argument("--seeds", type=int, default=20)
    parser.add_argument("--seed-base", type=int, default=1000)
    parser.add_argument("--output-root", default="runs")
    args = parser.parse_args(argv)

    tiers = ("exact", "scaling") if args.tier == "both" else (args.tier,)
    reprs = tuple(args.reprs.split(","))
    labs = ("A", "B") if args.lab == "both" else (args.lab,)

    metrics = run_experiment(tiers=tiers, reprs=reprs, labs=labs, seeds=args.seeds, seed_base=args.seed_base)

    run_dir = Path(args.output_root) / utc_run_id()
    run_dir.mkdir(parents=True, exist_ok=True)
    config = {
        "experiment": "spatial_lab",
        "tiers": list(tiers),
        "reprs": list(reprs),
        "labs": list(labs),
        "seeds": args.seeds,
        "determinism_commitment": sha256_hex({"kind": "spatial_lab_seed", "seed": args.seed_base}),
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
