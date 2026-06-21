"""Geometric Formation Lab v1 experiment harness."""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from spatial_swarm.experiments.metrics import process_resource_use, write_metrics, write_metrics_and_digest
from spatial_swarm.experiments.redaction import redaction_report
from spatial_swarm.experiments.report import utc_run_id, write_environment, write_git_commit, write_yaml_like
from spatial_swarm.spatial_puzzle.geometry_lab.attacks import (
    MUTATION_TESTS,
    PARTIAL_COMPROMISE_LEVELS,
    SYMMETRY_TESTS,
    TOPOLOGY_TESTS,
    attack_suite_for_family,
    mutate_for_attack,
)
from spatial_swarm.spatial_puzzle.geometry_lab.families import (
    FAMILY_NAMES,
    base_target_bits,
    endpoint_margin,
    estimated_runtime_ms,
    forbidden_region_margin,
    generate_family_spec,
    generation_failed,
    generation_failure_rate,
    leakage_bits_lost,
    path_length_stats,
    profile_for,
    symmetry_ambiguity_count,
)
from spatial_swarm.spatial_puzzle.geometry_lab.metrics import (
    geometry_value_score,
    summarize_decisions,
    summary_values,
    write_csv,
)
from spatial_swarm.spatial_puzzle.geometry_lab.verifier import (
    ABLATION_CONFIGS,
    BASELINE_CONFIGS,
    FULL_GEOMETRY,
    GeometryVerifier,
    PresentedFormation,
    config_for_ablation,
    config_for_baseline,
)


def run_experiment(
    *,
    families: tuple[str, ...] = FAMILY_NAMES,
    agent_counts: tuple[int, ...] = (5, 10, 20, 50, 100),
    trials: int = 500,
    attack_trials: int = 1000,
    partial_compromise_trials: int = 1000,
    mutation_trials: int = 500,
    ablation_trials: int = 300,
    grid_size: int = 64,
    time_steps: int = 24,
) -> tuple[dict, dict[str, list[dict]]]:
    csv_rows: dict[str, list[dict]] = defaultdict(list)
    generation = _run_generation(families, agent_counts, trials, grid_size, time_steps, csv_rows)
    attack_matrix = _run_attack_matrix(families, attack_trials, grid_size, time_steps, csv_rows)
    partial = _run_partial_compromise(
        families,
        agent_counts,
        partial_compromise_trials,
        grid_size,
        time_steps,
        csv_rows,
    )
    rigidity = _run_rigidity(families, mutation_trials, grid_size, time_steps, csv_rows)
    symmetry = _run_symmetry(families, mutation_trials, grid_size, time_steps, csv_rows)
    topology = _run_topology(mutation_trials, grid_size, time_steps, csv_rows)
    ablations = _run_ablations(families, ablation_trials, grid_size, time_steps, csv_rows)
    baselines = _run_baselines(families, ablation_trials, grid_size, time_steps, csv_rows)
    value = _run_value_summary(families, generation, attack_matrix, partial, csv_rows)
    metrics = {
        "experiment": "geometric_formation_lab_v1",
        "status": "formation_family_boundary_stress",
        "config": {
            "families": list(families),
            "agents": list(agent_counts),
            "trials": trials,
            "attack_trials": attack_trials,
            "partial_compromise_trials": partial_compromise_trials,
            "mutation_trials": mutation_trials,
            "ablation_trials": ablation_trials,
            "grid_size": grid_size,
            "time_steps": time_steps,
            "v2_wrapper_baseline_tag": "realistic-coding-gate-v2",
            "v2_wrapper_fixed": True,
        },
        "generation": generation,
        "attack_matrix": attack_matrix,
        "partial_compromise_leakage": partial,
        "rigidity": rigidity,
        "symmetry": symmetry,
        "topology": topology,
        "ablations": ablations,
        "baselines": baselines,
        "geometry_value": value,
    }
    return metrics, dict(csv_rows)


def _run_generation(
    families: tuple[str, ...],
    agent_counts: tuple[int, ...],
    trials: int,
    grid_size: int,
    time_steps: int,
    csv_rows: dict[str, list[dict]],
) -> dict:
    out = {}
    for family in families:
        out[family] = {}
        for agents in agent_counts:
            failures = 0
            false_blocks = 0
            runtimes: list[float] = []
            path_means: list[float] = []
            path_vars: list[float] = []
            endpoint_margins: list[float] = []
            forbidden_margins: list[float] = []
            for trial in range(trials):
                if generation_failed(family, agents, trial):
                    failures += 1
                    continue
                spec = generate_family_spec(
                    family,
                    agents,
                    trial,
                    grid_size=grid_size,
                    time_steps=time_steps,
                )
                decision = GeometryVerifier(FULL_GEOMETRY).verify(spec, PresentedFormation.from_spec(spec))
                false_blocks += int(decision.blocked)
                runtimes.append(decision.verification_runtime_ms)
                stats = path_length_stats(spec)
                path_means.append(stats["mean"])
                path_vars.append(stats["variance"])
                endpoint_margins.append(endpoint_margin(spec))
                forbidden_margins.append(
                    forbidden_region_margin(tuple(path for _, path in spec.paths), spec.obstacle_map)
                )
            generated = trials - failures
            false_block_rate = false_blocks / generated if generated else 0.0
            generation_failure = failures / trials if trials else 0.0
            row = {
                "family": family,
                "agents": agents,
                "attempts": trials,
                "generated": generated,
                "generation_failures": failures,
                "generation_failure_rate": generation_failure,
                "expected_generation_failure_rate": generation_failure_rate(family, agents),
                "false_blocks": false_blocks,
                "false_block_rate": false_block_rate,
                "runtime_p50_ms": summary_values(runtimes)["p50"],
                "runtime_p95_ms": summary_values(runtimes)["p95"],
                "path_length_mean": summary_values(path_means)["p50"],
                "path_length_variance": summary_values(path_vars)["p50"],
                "endpoint_margin_p50": summary_values(endpoint_margins)["p50"],
                "forbidden_region_margin_p50": summary_values(forbidden_margins)["p50"],
                "symmetry_ambiguity_count": symmetry_ambiguity_count(family, agents),
            }
            out[family][str(agents)] = row
            csv_rows["geometry_family_summary"].append(row)
            csv_rows["runtime_scaling"].append(
                {
                    "family": family,
                    "agents": agents,
                    "runtime_p50_ms": row["runtime_p50_ms"],
                    "runtime_p95_ms": row["runtime_p95_ms"],
                    "false_block_rate": false_block_rate,
                    "generation_failure_rate": generation_failure,
                }
            )
    return out


def _run_attack_matrix(
    families: tuple[str, ...],
    attack_trials: int,
    grid_size: int,
    time_steps: int,
    csv_rows: dict[str, list[dict]],
) -> dict:
    out = {}
    for family in families:
        out[family] = {}
        specs = [
            generate_family_spec(family, 20, 100_000 + trial, grid_size=grid_size, time_steps=time_steps)
            for trial in range(attack_trials)
        ]
        for attack in attack_suite_for_family(family):
            rows = []
            for trial, spec in enumerate(specs):
                presented = mutate_for_attack(PresentedFormation.from_spec(spec), attack, trial)
                decision = GeometryVerifier(FULL_GEOMETRY).verify(spec, presented)
                rows.append(_decision_row(decision))
            summary = summarize_decisions(rows)
            out[family][attack.name] = {
                "category": attack.category,
                "violated_features": list(attack.violated_features),
                **summary,
            }
            csv_rows["attack_matrix"].append(
                {
                    "family": family,
                    "attack": attack.name,
                    "category": attack.category,
                    "violated_features": ",".join(attack.violated_features),
                    "attempts": summary["attempts"],
                    "release_rate": summary["release"]["rate"],
                    "block_rate": summary["blocked"]["rate"],
                    "runtime_p95_ms": summary["verification_runtime_ms"]["p95"],
                    "main_reasons": ";".join(summary["internal_reasons"].keys()),
                }
            )
    return out


def _run_partial_compromise(
    families: tuple[str, ...],
    agent_counts: tuple[int, ...],
    trials: int,
    grid_size: int,
    time_steps: int,
    csv_rows: dict[str, list[dict]],
) -> dict:
    out = {}
    for family in families:
        out[family] = {}
        for agents in agent_counts:
            out[family][str(agents)] = {}
            base_bits = base_target_bits(family, agents, grid_size, time_steps)
            for access in PARTIAL_COMPROMISE_LEVELS:
                bits_lost_values = [leakage_bits_lost(family, access, agents, trial) for trial in range(trials)]
                residual_values = [max(0.0, base_bits - lost) for lost in bits_lost_values]
                one_shot = [2 ** (-bits) for bits in residual_values]
                row = {
                    "family": family,
                    "agents": agents,
                    "access": access,
                    "attempts": trials,
                    "target_bits_a0": base_bits,
                    "bits_lost_p50": summary_values(bits_lost_values)["p50"],
                    "bits_lost_p95": summary_values(bits_lost_values)["p95"],
                    "residual_bits_p50": summary_values(residual_values)["p50"],
                    "one_shot_success_p50": summary_values(one_shot)["p50"],
                    "leakage_from_one_stolen_agent": summary_values(bits_lost_values)["p50"]
                    if access == "A2_one_stolen_agent"
                    else 0.0,
                    "leakage_from_two_stolen_agents": summary_values(bits_lost_values)["p50"]
                    if access == "A3_two_stolen_agents"
                    else 0.0,
                }
                out[family][str(agents)][access] = row
                csv_rows["partial_compromise_leakage"].append(row)
    return out


def _run_rigidity(
    families: tuple[str, ...],
    mutation_trials: int,
    grid_size: int,
    time_steps: int,
    csv_rows: dict[str, list[dict]],
) -> dict:
    out = {}
    for family in families:
        out[family] = {}
        specs = [
            generate_family_spec(family, 20, 200_000 + trial, grid_size=grid_size, time_steps=time_steps)
            for trial in range(mutation_trials)
        ]
        for mutation in MUTATION_TESTS:
            rows = []
            for trial, spec in enumerate(specs):
                presented = mutate_for_attack(PresentedFormation.from_spec(spec), mutation, trial)
                decision = GeometryVerifier(FULL_GEOMETRY).verify(spec, presented)
                rows.append(_decision_row(decision))
            summary = summarize_decisions(rows)
            out[family][mutation.name] = summary
            csv_rows["rigidity_mutation_results"].append(
                {
                    "family": family,
                    "mutation": mutation.name,
                    "attempts": summary["attempts"],
                    "mutation_survival_rate": summary["release"]["rate"],
                    "block_rate": summary["blocked"]["rate"],
                    "main_reasons": ";".join(summary["internal_reasons"].keys()),
                }
            )
    return out


def _run_symmetry(
    families: tuple[str, ...],
    mutation_trials: int,
    grid_size: int,
    time_steps: int,
    csv_rows: dict[str, list[dict]],
) -> dict:
    out = {}
    for family in families:
        out[family] = {}
        specs = [
            generate_family_spec(family, 20, 300_000 + trial, grid_size=grid_size, time_steps=time_steps)
            for trial in range(mutation_trials)
        ]
        for test in SYMMETRY_TESTS:
            rows = []
            for trial, spec in enumerate(specs):
                presented = mutate_for_attack(PresentedFormation.from_spec(spec), test, trial)
                decision = GeometryVerifier(FULL_GEOMETRY).verify(spec, presented)
                rows.append(_decision_row(decision))
            summary = summarize_decisions(rows)
            ambiguity = symmetry_ambiguity_count(family, 20)
            out[family][test.name] = {**summary, "symmetry_ambiguity_count": ambiguity}
            csv_rows["symmetry_results"].append(
                {
                    "family": family,
                    "symmetry_test": test.name,
                    "attempts": summary["attempts"],
                    "release_rate": summary["release"]["rate"],
                    "symmetry_ambiguity_count": ambiguity,
                    "main_reasons": ";".join(summary["internal_reasons"].keys()),
                }
            )
    return out


def _run_topology(
    mutation_trials: int,
    grid_size: int,
    time_steps: int,
    csv_rows: dict[str, list[dict]],
) -> dict:
    out = {}
    specs = [
        generate_family_spec("braid", 20, 400_000 + trial, grid_size=grid_size, time_steps=time_steps)
        for trial in range(mutation_trials)
    ]
    for test in TOPOLOGY_TESTS:
        rows = []
        for trial, spec in enumerate(specs):
            presented = mutate_for_attack(PresentedFormation.from_spec(spec), test, trial)
            decision = GeometryVerifier(FULL_GEOMETRY).verify(spec, presented)
            rows.append(_decision_row(decision))
        summary = summarize_decisions(rows)
        out[test.name] = summary
        csv_rows["topology_results"].append(
            {
                "family": "braid",
                "topology_test": test.name,
                "attempts": summary["attempts"],
                "topology_attack_release": summary["release"]["rate"],
                "topology_near_miss_survival": summary["release"]["rate"],
                "topology_runtime_cost": summary["verification_runtime_ms"]["p95"],
                "main_reasons": ";".join(summary["internal_reasons"].keys()),
            }
        )
    return out


def _run_ablations(
    families: tuple[str, ...],
    ablation_trials: int,
    grid_size: int,
    time_steps: int,
    csv_rows: dict[str, list[dict]],
) -> dict:
    out = {}
    for family in families:
        out[family] = {}
        attacks = attack_suite_for_family(family)
        specs = [
            generate_family_spec(family, 20, 500_000 + trial, grid_size=grid_size, time_steps=time_steps)
            for trial in range(ablation_trials)
        ]
        for ablation in ABLATION_CONFIGS:
            config = config_for_ablation(ablation)
            rows = []
            for attack in attacks:
                for trial, spec in enumerate(specs):
                    presented = mutate_for_attack(PresentedFormation.from_spec(spec), attack, trial)
                    decision = GeometryVerifier(config).verify(spec, presented)
                    rows.append(_decision_row(decision))
            summary = summarize_decisions(rows)
            out[family][ablation] = summary
            csv_rows["ablation_results"].append(
                {
                    "family": family,
                    "ablation": ablation,
                    "attempts": summary["attempts"],
                    "attack_release_rate": summary["release"]["rate"],
                    "block_rate": summary["blocked"]["rate"],
                    "runtime_p95_ms": summary["verification_runtime_ms"]["p95"],
                    "main_reasons": ";".join(summary["internal_reasons"].keys()),
                }
            )
    return out


def _run_baselines(
    families: tuple[str, ...],
    baseline_trials: int,
    grid_size: int,
    time_steps: int,
    csv_rows: dict[str, list[dict]],
) -> dict:
    out = {}
    for family in families:
        out[family] = {}
        attacks = attack_suite_for_family(family)
        specs = [
            generate_family_spec(family, 20, 600_000 + trial, grid_size=grid_size, time_steps=time_steps)
            for trial in range(baseline_trials)
        ]
        for baseline in BASELINE_CONFIGS:
            rows = []
            verifier = GeometryVerifier(config_for_baseline(baseline))
            for attack in attacks:
                for trial, spec in enumerate(specs):
                    presented = mutate_for_attack(PresentedFormation.from_spec(spec), attack, trial)
                    rows.append(_decision_row(verifier.verify(spec, presented)))
            summary = summarize_decisions(rows)
            out[family][baseline] = summary
            csv_rows["baseline_results"].append(
                {
                    "family": family,
                    "baseline": baseline,
                    "attempts": summary["attempts"],
                    "attack_release_rate": summary["release"]["rate"],
                    "block_rate": summary["blocked"]["rate"],
                    "main_reasons": ";".join(summary["internal_reasons"].keys()),
                }
            )
    return out


def _run_value_summary(
    families: tuple[str, ...],
    generation: dict,
    attack_matrix: dict,
    partial: dict,
    csv_rows: dict[str, list[dict]],
) -> dict:
    out = {}
    for family in families:
        reference_agents = "20" if "20" in generation[family] else sorted(
            generation[family],
            key=lambda value: int(value),
        )[-1]
        attack_rows = attack_matrix[family].values()
        attack_block_rate = sum(row["blocked"]["rate"] for row in attack_rows) / len(attack_matrix[family])
        false_block_rate = generation[family][reference_agents]["false_block_rate"]
        runtime_p95_ms = generation[family][reference_agents]["runtime_p95_ms"]
        target_bits = partial[family][reference_agents]["A0_public_only"]["target_bits_a0"]
        bits_lost_a3 = partial[family][reference_agents]["A3_two_stolen_agents"]["bits_lost_p50"]
        score = geometry_value_score(
            attack_block_rate=attack_block_rate,
            false_block_rate=false_block_rate,
            runtime_p95_ms=runtime_p95_ms,
            leakage_bits_lost_a3=bits_lost_a3,
            target_bits_a0=target_bits,
        )
        out[family] = {
            **score,
            "runtime_p95_ms": runtime_p95_ms,
            "target_bits_a0": target_bits,
            "bits_lost_a3": bits_lost_a3,
            "profile_notes": profile_for(family).notes,
        }
        csv_rows["geometry_value_results"].append({"family": family, **out[family]})
    return out


def _decision_row(decision) -> dict:
    return {
        "released": decision.released,
        "blocked": decision.blocked,
        "internal_reasons": decision.internal_reasons,
        "checks_performed": decision.checks_performed,
        "verification_runtime_ms": decision.verification_runtime_ms,
    }


def write_artifacts(run_dir: Path, metrics: dict, csv_rows: dict[str, list[dict]]) -> None:
    for name, rows in csv_rows.items():
        write_csv(run_dir / f"{name}.csv", rows)
    examples = run_dir / "formation_examples"
    examples.mkdir(parents=True, exist_ok=True)
    for family in metrics["config"]["families"]:
        spec = generate_family_spec(family, 5, 0)
        (examples / f"{family}.json").write_text(
            json.dumps(spec.canonical_public(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )


def summary_md(metrics: dict) -> str:
    lines = ["# Geometric Formation Lab v1 summary", ""]
    lines.append(f"- families: {', '.join(metrics['config']['families'])}")
    lines.append(f"- agents: {metrics['config']['agents']}")
    lines.append(f"- trials: {metrics['config']['trials']}")
    lines.append(f"- attack_trials: {metrics['config']['attack_trials']}")
    lines.append(f"- partial_compromise_trials: {metrics['config']['partial_compromise_trials']}")
    lines.append(f"- mutation_trials: {metrics['config']['mutation_trials']}")
    lines.append(f"- ablation_trials: {metrics['config']['ablation_trials']}")
    lines.append("")
    lines.append("| family | geometry value | attack block | A3 bits lost | runtime p95 ms |")
    lines.append("| --- | ---: | ---: | ---: | ---: |")
    for family, row in sorted(
        metrics["geometry_value"].items(),
        key=lambda item: item[1]["geometry_value_score"],
        reverse=True,
    ):
        lines.append(
            f"| {family} | {row['geometry_value_score']:.3f} | "
            f"{row['attacks_blocked_by_geometry']:.3f} | {row['bits_lost_a3']:.3f} | "
            f"{row['runtime_p95_ms']:.3f} |"
        )
    lines.append("")
    lines.append("Report family rankings as model observations, not production security proofs.")
    return "\n".join(lines) + "\n"


def main(argv: Optional[list[str]] = None) -> Path:
    parser = argparse.ArgumentParser(description="Run Geometric Formation Lab v1.")
    parser.add_argument("--families", default=",".join(FAMILY_NAMES))
    parser.add_argument("--agents", default="5,10,20,50,100")
    parser.add_argument("--trials", type=int, default=500)
    parser.add_argument("--attack-trials", type=int, default=1000)
    parser.add_argument("--partial-compromise-trials", type=int, default=1000)
    parser.add_argument("--mutation-trials", type=int, default=500)
    parser.add_argument("--ablation-trials", type=int, default=300)
    parser.add_argument("--grid-size", type=int, default=64)
    parser.add_argument("--time-steps", type=int, default=24)
    parser.add_argument("--output-root", default="runs")
    parser.add_argument("--quick", action="store_true", help="Use 100-count smoke settings unless counts are overridden.")
    args = parser.parse_args(argv)
    families = tuple(part.strip() for part in args.families.split(",") if part.strip())
    agents = tuple(int(part) for part in args.agents.split(",") if part.strip())
    if args.quick:
        args.trials = min(args.trials, 100)
        args.attack_trials = min(args.attack_trials, 100)
        args.partial_compromise_trials = min(args.partial_compromise_trials, 100)
        args.mutation_trials = min(args.mutation_trials, 100)
        args.ablation_trials = min(args.ablation_trials, 100)
    metrics, csv_rows = run_experiment(
        families=families,
        agent_counts=agents,
        trials=args.trials,
        attack_trials=args.attack_trials,
        partial_compromise_trials=args.partial_compromise_trials,
        mutation_trials=args.mutation_trials,
        ablation_trials=args.ablation_trials,
        grid_size=args.grid_size,
        time_steps=args.time_steps,
    )
    run_dir = Path(args.output_root) / utc_run_id()
    run_dir.mkdir(parents=True, exist_ok=True)
    write_yaml_like(run_dir / "config.yaml", metrics["config"])
    write_environment(run_dir)
    write_git_commit(run_dir)
    full = dict(metrics)
    full["resource_use"] = process_resource_use()
    write_metrics_and_digest(run_dir / "metrics.json", full)
    write_artifacts(run_dir, metrics, csv_rows)
    (run_dir / "summary.md").write_text(summary_md(metrics), encoding="utf-8")
    write_metrics(run_dir / "redaction.json", redaction_report(run_dir))
    print(run_dir)
    return run_dir


if __name__ == "__main__":
    main()
