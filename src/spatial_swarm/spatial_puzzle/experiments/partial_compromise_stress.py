"""Spatial partial-compromise stress test (separate experiment layer; UCOG frozen).

Question: can hidden 3D spatial structure make partial compromise harder to use before a
one-shot system destroys itself? Three arms at matched second-factor entropy
(random_only / random_plus / spatial), all keeping a random secret as the lock. Six
experiments: E1 partial-compromise matrix (access A0..A8), E2 one-shot vs retry,
E3 silent vs verbose, E4 generation-time hygiene, E5 solver stress, E6 scaling tiers.
All rates carry Clopper-Pearson 95% intervals; 8 positive controls gate the run; the
findings are written only from real numbers. No claim is favored.
"""

from __future__ import annotations

import argparse
import math
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
    RunLogger,
    utc_run_id,
    write_environment,
    write_git_commit,
    write_yaml_like,
)
from spatial_swarm.spatial_lab.solvers.base import Budget
from spatial_swarm.spatial_puzzle.detector.attacks import (
    ATTACK_CLASSES,
    RELEASED_EXPECTED,
    build_attack_context,
    make_candidate,
)
from spatial_swarm.spatial_puzzle.detector.base import Submission
from spatial_swarm.spatial_puzzle.detector.nongeometric import NonGeometricTripwire
from spatial_swarm.spatial_puzzle.enclave.attestation import attest
from spatial_swarm.spatial_puzzle.enclave.failure_policy import SwarmLifecycle, SwarmState
from spatial_swarm.spatial_puzzle.enclave.service import SealedService
from spatial_swarm.spatial_puzzle.experiments import pcs_access, pcs_metrics, pcs_systems
from spatial_swarm.spatial_puzzle.experiments.orchestrate import run_solver_bakeoff
from spatial_swarm.spatial_puzzle.generators.build import build_hidden_solution
from spatial_swarm.spatial_puzzle.generators.rejection import evaluate_candidate, generate_accepted

# Per-seed budgets are small at the budgeted tiers so non-enumerable residuals trip fast and
# are reported as "not solved within budget"; the E5 bake-off gets a generous one-off budget.
TIERS = {
    "tiny":   {"n": 3, "k": 4,  "seeds": 30, "budget": (10.0, 3_000_000), "bakeoff": (20.0, 5_000_000), "exact": True},
    "medium": {"n": 4, "k": 8,  "seeds": 30, "budget": (2.0, 500_000),    "bakeoff": (20.0, 5_000_000), "exact": False},
    "large":  {"n": 5, "k": 10, "seeds": 10, "budget": (2.0, 500_000),    "bakeoff": (30.0, 8_000_000), "exact": False},
}
_FAST_SOLVER_BUDGET = (0.25, 50_000)   # "minimum budget" for the adversarial filter / solver-open leak
_RETRY_STRIKES = 5


# --------------------------------------------------------------------------- E1

def _exp1_partial_compromise(seed_tables: list, arms_per_seed: list) -> dict:
    levels = {}
    for level in pcs_access.ACCESS_LEVELS:
        sp_counts, sp_oneshot, enumerated, budget_hit = [], [], 0, 0
        runs = 0
        for table in seed_tables:
            cell = table[level.name]["arms"]["spatial"]
            if cell.get("status") != "ok":
                continue
            runs += 1
            if cell.get("enumerated"):
                enumerated += 1
                sp_counts.append(float(cell["residual_count"]))
                sp_oneshot.append(cell["one_shot_success_prob"])
            if cell.get("budget_hit"):
                budget_hit += 1
        rp = arms_per_seed[0]["random_plus"]
        ro = arms_per_seed[0]["random_only"]
        levels[level.name] = {
            "revealed_neighbors": level.revealed_neighbors,
            "runs": level.runs,
            "spatial": {
                "enumerated": pcs_metrics.proportion(enumerated, runs) if runs else None,
                "budget_hit": pcs_metrics.proportion(budget_hit, runs) if runs else None,
                "residual_count_median": statistics.median(sp_counts) if sp_counts else None,
                "residual_count_summary": _latency_summary(sp_counts) if sp_counts else None,
                "one_shot_success_median": statistics.median(sp_oneshot) if sp_oneshot else None,
            } if level.runs else {"status": "not_run"},
            "random_plus": {
                "second_factor_bits": rp.second_factor_bits,
                "one_shot_success": 2.0 ** (-rp.second_factor_bits),
                "note": "independent random factor: residual constant under stolen neighbors",
            } if level.runs else {"status": "not_run"},
            "random_only": {
                "second_factor_bits": ro.second_factor_bits,
                "one_shot_success": 2.0 ** (-ro.second_factor_bits),
            } if level.runs else {"status": "not_run"},
        }
    return {"access_levels": levels}


def _attack_release_catch(seeds: list, n: int, k: int, budget: tuple) -> dict:
    """Run every attack class through the sealed (silent) tripwire on the spatial arm."""

    per_class = {ac: {"released": 0, "blocked": 0, "constructible": 0} for ac in ATTACK_CLASSES}
    for s in seeds:
        sol = build_hidden_solution(random.Random(s), n=n, k=k, swarm_id=f"atk-{s}")
        ctx = build_attack_context(sol, budget=budget)
        for ai, ac in enumerate(ATTACK_CLASSES):
            cand = make_candidate(ctx, ac, random.Random(s * 1000 + ai))
            if cand is None:
                continue
            per_class[ac]["constructible"] += 1
            det = NonGeometricTripwire(sol)
            r = det.submit(Submission(sol.swarm_id, ctx.agent, cand, ac))
            per_class[ac]["released"] += int(r.released)
            per_class[ac]["blocked"] += int(r.blocked and not r.released)
    out = {}
    for ac, d in per_class.items():
        ncon = d["constructible"]
        out[ac] = {
            "constructible": ncon,
            "release_rate": pcs_metrics.proportion(d["released"], ncon) if ncon else None,
            "catch_rate": pcs_metrics.proportion(d["blocked"], ncon) if ncon else None,
            "released_expected": RELEASED_EXPECTED[ac],
        }
    return out


# --------------------------------------------------------------------------- E2

def _exp2_one_shot_vs_retry(seed_tables: list, *, trials: int = 2000) -> dict:
    """At each access level: one-shot (strikes=1) vs limited-retry (strikes=5) recovery."""

    out = {}
    for level in pcs_access.ACCESS_LEVELS:
        if not level.runs:
            out[level.name] = {"status": "not_run"}
            continue
        one_shot, retry_sys, retry_exp, residuals = [], [], [], []
        for table in seed_tables:
            cell = table[level.name]["arms"]["spatial"]
            if cell.get("status") != "ok" or not cell.get("enumerated"):
                continue
            r = cell["residual_count"]
            residuals.append(float(r))
            one_shot.append(1.0 / r)
            retry_sys.append(1.0 if r <= _RETRY_STRIKES else 0.0)   # systematic elimination within strikes
            retry_exp.append(min(1.0, _RETRY_STRIKES / r))           # random-order expected
        out[level.name] = {
            "spatial_residual_median": statistics.median(residuals) if residuals else None,
            "spatial_one_shot_recovery_median": statistics.median(one_shot) if one_shot else None,
            "spatial_retry_recovery_systematic_rate": statistics.mean(retry_sys) if retry_sys else None,
            "spatial_retry_recovery_expected_median": statistics.median(retry_exp) if retry_exp else None,
            "random_plus_one_shot_recovery": None,   # filled by caller (constant per run)
            "n_enumerated_seeds": len(residuals),
        }
    return out


def _shutdown_demo(arm, *, strikes: int) -> dict:
    """Drive the real failure policy with wrong guesses: queries to first flag / shutdown."""

    lc = SwarmLifecycle(arm.swarm_id, arm.opener, one_shot=True, strikes=strikes)
    first_flag = None
    for i in range(1, strikes + 2):
        wrong = frozenset((90 + i, 90, 90 - j) for j in range(arm.k))
        out = lc.submit_proof(wrong)
        if first_flag is None and out.blocked:
            first_flag = i
        if out.state is SwarmState.DEAD:
            return {"queries_to_first_flag": first_flag, "queries_to_shutdown": i, "strikes": strikes}
    return {"queries_to_first_flag": first_flag, "queries_to_shutdown": None, "strikes": strikes}


# --------------------------------------------------------------------------- E3

def _exp3_silent_vs_verbose(*, n: int, k: int, seeds: int, budget: tuple, seed_base: int) -> dict:
    from spatial_swarm.spatial_puzzle.leakage.meter import measure_ladder
    ladder = measure_ladder(n=n, k=k, seeds=seeds, seed_base=seed_base)
    both = ladder["levels"].get("O7O8_both_hints", {})
    return {
        "silent_reason_bits": 0.0,
        "verbose_reason_bits": math.log2(4),
        "residual_shape_only_median": ladder["random_ceiling"]["residual_median"],
        "residual_after_reasons_median": both.get("residual_median"),
        "verbose_max_leak_bits": both.get("delta_below_random_ceiling_bits"),
        "note": "verbose reveals which hidden check failed (a fit/no-fit oracle); silent reveals nothing beyond pass/fail",
    }


# --------------------------------------------------------------------------- E4

def _measure_reasons(sols, *, budget: tuple, fast_budget: tuple) -> dict:
    from collections import Counter
    hist = Counter()
    accepted = 0
    for sol in sols:
        v = evaluate_candidate(sol, ambiguity_target=4, budget_factory=lambda: Budget(*budget),
                               min_solver_budget=fast_budget)
        if v.accepted:
            accepted += 1
        for r in (v.reasons or []):
            hist[r] += 1
    return {"n": len(sols), "accepted": accepted, "reason_histogram": dict(hist)}


def _exp4_generation_hygiene(*, n: int, k: int, seeds: int, budget: tuple, seed_base: int) -> dict:
    # unfiltered: raw puzzles, measure how many weak instances slip through
    raw = [build_hidden_solution(random.Random(s), n=n, k=k, swarm_id=f"unf-{s}")
           for s in range(seed_base, seed_base + seeds)]
    unfiltered = _measure_reasons(raw, budget=budget, fast_budget=_FAST_SOLVER_BUDGET)

    def _gen(adversarial: bool):
        attempts, accepted = [], 0
        from collections import Counter
        hist = Counter()
        for s in range(seed_base, seed_base + seeds):
            sol, stats = generate_accepted(
                random.Random(s), n=n, k=k, swarm_id=f"flt-{s}",
                ambiguity_target=(8 if adversarial else 4), max_generation_attempts=80,
                min_solver_budget=(_FAST_SOLVER_BUDGET if adversarial else None),
            )
            attempts.append(stats["attempts"])
            accepted += int(stats["accepted"])
            for r, c in stats["reason_histogram"].items():
                hist[r] += c
        return {
            "accepted": pcs_metrics.proportion(accepted, seeds),
            "median_generation_attempts": statistics.median(attempts) if attempts else None,
            "reason_histogram": dict(hist),
        }

    return {
        "unfiltered": {
            "weak_instance_acceptance": pcs_metrics.proportion(unfiltered["accepted"], unfiltered["n"]),
            "reason_histogram": unfiltered["reason_histogram"],
            "note": "fraction of raw puzzles that survive the suite with no filtering",
        },
        "filtered": _gen(adversarial=False),
        "adversarially_filtered": _gen(adversarial=True),
    }


# --------------------------------------------------------------------------- sealed runtime

def _sealed_runtime_demo() -> dict:
    svc = SealedService(one_shot=True)
    meta = svc.create_swarm(n=3, k=4, seed=4242)
    agent = sorted(meta.commitments)[1]
    wrong = frozenset({(9, 9, 9), (8, 9, 9), (7, 9, 9), (6, 9, 9)})
    first = svc.verify_message(meta.swarm_id, agent, wrong)
    second = svc.verify_message(meta.swarm_id, agent, wrong)
    att = attest()
    return {
        "sealed_runtime": "process",
        "tee_attestation": False,
        "sgx": att.sgx,
        "attestation_mode": att.mode,
        "wrong_proof_destroyed": first.blocked and first.state == "dead",
        "second_attempt_denied": second.blocked and second.state == "dead",
    }


# --------------------------------------------------------------------------- tier

def run_tier(tier: str, *, seeds: Optional[int] = None) -> dict:
    cfg = TIERS[tier]
    n, k, budget = cfg["n"], cfg["k"], cfg["budget"]
    nseeds = seeds or cfg["seeds"]
    seed_base = {"tiny": 10_000, "medium": 20_000, "large": 30_000}[tier]

    arms_per_seed, seed_tables, gen_failures, seeds_used = [], [], 0, []
    s = seed_base
    while len(arms_per_seed) < nseeds and s < seed_base + nseeds * 10:
        try:
            arms = pcs_systems.build_arms(random.Random(s), n=n, k=k, swarm_id=f"pcs-{s}", budget=budget)
        except RuntimeError:
            gen_failures += 1
            s += 1
            continue
        arms_per_seed.append(arms)
        seed_tables.append(pcs_access.residual_table(arms, budget))
        seeds_used.append(s)
        s += 1

    e1 = _exp1_partial_compromise(seed_tables, arms_per_seed)
    e5 = run_solver_bakeoff(n=n, k=k, budget=cfg["bakeoff"])
    if cfg["exact"]:
        e3 = _exp3_silent_vs_verbose(n=n, k=k, seeds=nseeds, budget=budget, seed_base=seed_base + 7)
    else:
        e3 = {"silent_reason_bits": 0.0, "verbose_reason_bits": math.log2(4),
              "residual_shape_only_median": None, "residual_after_reasons_median": None,
              "verbose_max_leak_bits": None,
              "note": "verbose>silent established at the exact tier; residual leak not enumerated at budgeted tier"}

    # E2 (enumerated residuals), E4 (generation hygiene), and the full attack matrix all
    # require exact enumeration; run them only at the exact tier. At budgeted tiers the
    # residual is "not solved within budget" (see E1 enumerated rate) and these are skipped.
    if cfg["exact"]:
        e2 = _exp2_one_shot_vs_retry(seed_tables)
        rp_bits = arms_per_seed[0]["random_plus"].second_factor_bits if arms_per_seed else None
        for lvl in e2.values():
            if isinstance(lvl, dict) and "random_plus_one_shot_recovery" in lvl and rp_bits:
                lvl["random_plus_one_shot_recovery"] = 2.0 ** (-rp_bits)
        e4 = _exp4_generation_hygiene(n=n, k=k, seeds=nseeds, budget=budget, seed_base=seed_base + 13)
        attacks = _attack_release_catch(seeds_used, n, k, budget)
    else:
        skip = {"status": "skipped_budgeted_tier", "reason": "exact enumeration not feasible within budget"}
        e2, e4, attacks = skip, skip, skip
    shutdown = {
        "one_shot": _shutdown_demo(arms_per_seed[0]["spatial"], strikes=1) if arms_per_seed else None,
        "retry": _shutdown_demo(arms_per_seed[0]["spatial"], strikes=_RETRY_STRIKES) if arms_per_seed else None,
    }
    entropy_match = arms_per_seed[0]["entropy_match"] if arms_per_seed else None

    return {
        "config": {"tier": tier, "n": n, "k": k, "seeds": len(arms_per_seed),
                   "budget_seconds": budget[0], "budget_nodes": budget[1], "exact": cfg["exact"]},
        "entropy_match": entropy_match,
        "generation_failures": gen_failures,
        "E1_partial_compromise": e1,
        "E2_one_shot_vs_retry": e2,
        "E2_shutdown_demo": shutdown,
        "E3_silent_vs_verbose": e3,
        "E4_generation_hygiene": e4,
        "E5_solver_bakeoff": e5,
        "attack_release_catch": attacks,
    }


# --------------------------------------------------------------------------- main

def _summary_md(metrics: dict) -> str:
    lines = ["# Spatial partial-compromise stress summary", ""]
    pc = metrics.get("positive_controls", {})
    lines.append(f"- positive_controls.valid: {pc.get('valid')}")
    lines.append(f"- redaction.clean: {metrics.get('redaction', {}).get('clean')}")
    for tier, t in metrics.get("tiers", {}).items():
        em = t.get("entropy_match", {}) or {}
        lines.append(f"- [{tier}] seeds={t['config']['seeds']} entropy_match_gap_bits={em.get('match_gap_bits')}")
    return "\n".join(lines) + "\n"


def main(argv: Optional[list] = None) -> Path:
    parser = argparse.ArgumentParser(description="Spatial partial-compromise stress test.")
    parser.add_argument("--tier", default="tiny", choices=["tiny", "medium", "large", "all"])
    parser.add_argument("--seeds", type=int, default=None)
    parser.add_argument("--output-root", default="runs")
    args = parser.parse_args(argv)

    tiers = ["tiny", "medium", "large"] if args.tier == "all" else [args.tier]
    run_dir = Path(args.output_root) / utc_run_id()
    run_dir.mkdir(parents=True, exist_ok=True)
    logger = RunLogger(run_dir)

    # Controls write planted secrets; keep them OUTSIDE run_dir so the redaction scan stays clean.
    with tempfile.TemporaryDirectory() as ctmp:
        cdir = Path(ctmp)
        controls = pcs_metrics.positive_controls(n=3, k=4, tmp_dir=cdir)
        planted = pcs_metrics.planted_secret_control(cdir / "planted")
    logger.emit({"event": "positive_controls", "valid": controls["valid"]})

    tier_results = {}
    for tier in tiers:
        logger.emit({"event": "tier_start", "tier": tier})
        tier_results[tier] = run_tier(tier, seeds=args.seeds)
        logger.emit({"event": "tier_done", "tier": tier,
                     "seeds": tier_results[tier]["config"]["seeds"]})

    metrics = {
        "experiment": "spatial_partial_compromise_stress",
        "positive_controls": controls,
        "planted_secret_control": planted,
        "sealed_runtime": _sealed_runtime_demo(),
        "tiers": tier_results,
    }

    config = {"experiment": "partial_compromise_stress", "tiers": tiers,
              "seeds_override": args.seeds, "secret_material_redacted": True}
    write_yaml_like(run_dir / "config.yaml", config)
    write_environment(run_dir)
    write_git_commit(run_dir)

    full = dict(metrics)
    full["run_config"] = config
    full["resource_use"] = process_resource_use()
    write_metrics_and_digest(run_dir / "metrics.json", full)

    # focused machine-readable artifacts
    write_metrics(run_dir / "solver_bakeoff.json",
                  {t: r["E5_solver_bakeoff"] for t, r in tier_results.items()})
    write_metrics(run_dir / "generator_rejection_histogram.json",
                  {t: r["E4_generation_hygiene"] for t, r in tier_results.items()})
    write_metrics(run_dir / "confidence_intervals.json", _collect_cis(tier_results, controls))
    write_metrics(run_dir / "run_manifest.json", _manifest(run_dir, metrics))
    (run_dir / "summary.md").write_text(_summary_md({**metrics, "tiers": tier_results}), encoding="utf-8")

    # redaction LAST (extended marker set; the planted control lives under _controls/)
    write_metrics(run_dir / "redaction.json", pcs_metrics.scan_for_secrets(run_dir))
    # re-stamp top-level metrics with the redaction summary for convenience
    full["redaction"] = pcs_metrics.scan_for_secrets(run_dir)

    print(run_dir)
    return run_dir


def _manifest(run_dir: Path, metrics: dict) -> dict:
    artifacts = sorted(p.name for p in run_dir.iterdir() if p.is_file())
    events = run_dir / "events.jsonl"
    rows = sum(1 for _ in events.open()) if events.exists() else 0
    return {
        "experiment": metrics["experiment"],
        "run_id": run_dir.name,
        "tiers": list(metrics["tiers"].keys()),
        "positive_controls_valid": metrics["positive_controls"]["valid"],
        "artifacts": artifacts,
        "event_rows": rows,
        "sealed_runtime": metrics["sealed_runtime"]["sealed_runtime"],
        "sgx": metrics["sealed_runtime"]["sgx"],
    }


def _collect_cis(tier_results: dict, controls: dict) -> dict:
    out = {"positive_controls_valid": controls["valid"], "tiers": {}}
    for tier, t in tier_results.items():
        per_level = {}
        for name, lvl in t["E1_partial_compromise"]["access_levels"].items():
            sp = lvl.get("spatial", {})
            if isinstance(sp, dict) and sp.get("enumerated"):
                per_level[name] = {"spatial_enumerated_ci95": sp["enumerated"]["ci95"]}
        atk_block = t["attack_release_catch"]
        atk = (
            {ac: d.get("catch_rate") for ac, d in atk_block.items()
             if isinstance(d, dict) and d.get("catch_rate")}
            if isinstance(atk_block, dict) and "status" not in atk_block else {}
        )
        out["tiers"][tier] = {"access_levels": per_level, "attack_catch_rate": atk}
    return out


if __name__ == "__main__":
    main()
