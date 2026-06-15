"""Keystone detector comparison: geometry vs a non-geometric tripwire.

Runs one shared attack suite through four detector variants (nongeometric baseline;
geometric silent / verbose / decoy) and reports, all with Clopper-Pearson CIs:
detection rate per attack class, false-positive rate on legit traffic,
queries-to-detection under repeated probing, and the bits a detector's response leaks
about the secret beyond pass/fail. The roll-up mirrors `run_fair_baseline_matrix`:
geometry's marginal detection advantage (expected 0), marginal leakage, FP delta.

Every catchable attack is caught by BOTH detectors via the commitment (the catch
floor), so detection rates are expected identical; the measured differences are the
verbose detector's extra leakage and the decoy detector's attribution signal.
"""

from __future__ import annotations

import math
import random

from spatial_swarm.experiments.metrics import _latency_summary
from spatial_swarm.experiments.stats import clopper_pearson
from spatial_swarm.spatial_puzzle.detector.attacks import (
    ATTACK_CLASSES,
    AttackContext,
    build_attack_context,
    make_candidate,
)
from spatial_swarm.spatial_puzzle.detector.base import Submission
from spatial_swarm.spatial_puzzle.detector.geometric import GeometricDetector
from spatial_swarm.spatial_puzzle.detector.nongeometric import NonGeometricTripwire
from spatial_swarm.spatial_puzzle.enclave.query_attacker import (
    binary_search_oracle,
    measure_one_shot_recovery,
)
from spatial_swarm.spatial_puzzle.generators.build import build_hidden_solution
from spatial_swarm.spatial_puzzle.leakage.meter import measure_ladder

DETECTOR_NAMES = ("nongeometric", "geometric_silent", "geometric_verbose", "geometric_decoy")
_GEO_VARIANTS = ("geometric_silent", "geometric_verbose", "geometric_decoy")
_BASELINE_REASONS = ("released", "wrong_proof_destroyed", "wrong_proof_retry", "swarm_dead")


def proportion(successes: int, n: int) -> dict:
    low, high = clopper_pearson(successes, n) if n else (0.0, 1.0)
    return {
        "successes": successes,
        "n": n,
        "rate": (successes / n if n else 0.0),
        "ci95": {"low": low, "high": high},
    }


def _make_detector(name: str, ctx: AttackContext, *, one_shot: bool, strikes: int):
    sol = ctx.sol
    if name == "nongeometric":
        return NonGeometricTripwire(sol, one_shot=one_shot, strikes=strikes)
    if name == "geometric_silent":
        return GeometricDetector(sol, one_shot=one_shot, strikes=strikes, reason_mode="silent")
    if name == "geometric_verbose":
        return GeometricDetector(sol, one_shot=one_shot, strikes=strikes, reason_mode="verbose")
    if name == "geometric_decoy":
        return GeometricDetector(
            sol, one_shot=one_shot, strikes=strikes, reason_mode="silent", decoy_hist=ctx.decoy_hist
        )
    raise ValueError(f"unknown detector: {name}")


def _detected(res) -> bool:
    return (res.blocked and not res.released) or res.flagged


def build_contexts(*, n: int, k: int, seeds: int, seed_base: int, budget: tuple[float, int]) -> list:
    contexts = []
    for s in range(seed_base, seed_base + seeds):
        sol = build_hidden_solution(random.Random(s), n=n, k=k, swarm_id=f"det-{s}")
        contexts.append(build_attack_context(sol, budget=budget))
    return contexts


def _attack_matrix(contexts: list, seed_base: int) -> dict:
    matrix: dict = {}
    for ai, ac in enumerate(ATTACK_CLASSES):
        per_det = {dn: {"detected": 0, "released": 0, "flagged": 0, "attributed": 0} for dn in DETECTOR_NAMES}
        constructible = 0
        for ci, ctx in enumerate(contexts):
            cand = make_candidate(ctx, ac, random.Random(seed_base + ai * 10_000 + ci))
            if cand is None:
                continue
            constructible += 1
            for dn in DETECTOR_NAMES:
                det = _make_detector(dn, ctx, one_shot=True, strikes=1)
                res = det.submit(Submission(ctx.sol.swarm_id, ctx.agent, cand, ac))
                per_det[dn]["detected"] += int(_detected(res))
                per_det[dn]["released"] += int(res.released)
                per_det[dn]["flagged"] += int(res.flagged)
                per_det[dn]["attributed"] += int(res.attribution is not None)
        matrix[ac] = {
            "constructible": constructible,
            "detectors": {
                dn: {
                    "detection": proportion(per_det[dn]["detected"], constructible),
                    "release_rate": proportion(per_det[dn]["released"], constructible),
                    "flag_rate": proportion(per_det[dn]["flagged"], constructible),
                    "attribution_rate": proportion(per_det[dn]["attributed"], constructible),
                }
                for dn in DETECTOR_NAMES
            },
        }
    return matrix


def _probing(contexts: list, *, strikes: int) -> dict:
    """Repeated wrong-proof probing with strikes>1: queries to first flag and to shutdown."""

    out: dict = {}
    for dn in ("nongeometric", "geometric_verbose"):
        first_flag, to_shutdown = [], []
        for ctx in contexts:
            det = _make_detector(dn, ctx, one_shot=True, strikes=strikes)
            stream = list(ctx.wrong_subsets)
            flagged_at = None
            shutdown_at = None
            for i, cand in enumerate(stream[:strikes], start=1):
                res = det.submit(Submission(ctx.sol.swarm_id, ctx.agent, cand, "repeated_adaptive_probe"))
                if flagged_at is None and res.flagged:
                    flagged_at = i
                if res.state == "dead":
                    shutdown_at = i
                    break
            if flagged_at is not None:
                first_flag.append(float(flagged_at))
            if shutdown_at is not None:
                to_shutdown.append(float(shutdown_at))
        out[dn] = {
            "queries_to_first_flag": _latency_summary(first_flag),
            "queries_to_shutdown": _latency_summary(to_shutdown),
            "strikes": strikes,
        }
    return out


def _leakage(*, n: int, k: int, seeds: int, seed_base: int, trials: int) -> dict:
    ladder = measure_ladder(n=n, k=k, seeds=seeds, seed_base=seed_base)
    r_shape = ladder["random_ceiling"]["residual_median"]
    both = ladder["levels"].get("O7O8_both_hints", {})
    r_clued = both.get("residual_median")
    leak_bits = both.get("delta_below_random_ceiling_bits")
    verbose = {
        "reason_vocabulary_bits": math.log2(4),
        "residual_shape_only_median": r_shape,
        "residual_both_hints_median": r_clued,
        "max_leak_bits": leak_bits,
        "note": "verbose reasons reveal the secret's connector/topology -> residual drops shape_only -> both_hints",
    }
    if r_shape:
        verbose["one_shot_recovery_shape_only"] = measure_one_shot_recovery(
            int(round(r_shape)), trials=trials, seed=1
        )
        verbose["oracle_queries_to_recover"] = binary_search_oracle(int(round(r_shape))).queries_before_recovery
    if r_clued:
        verbose["one_shot_recovery_after_leak"] = measure_one_shot_recovery(
            int(round(r_clued)), trials=trials, seed=1
        )
    return {
        "nongeometric": {"marginal_reason_bits": 0.0, "channel": "pass/fail (1 bit inherent to any gate)"},
        "geometric_silent": {"marginal_reason_bits": 0.0, "channel": "opaque reason, identical to baseline"},
        "geometric_verbose": verbose,
    }


def positive_controls(contexts: list) -> dict:
    """The gating controls; if any is False the run is invalid (a spurious advantage cannot survive)."""

    blind_ok = catch_ok = legit_ok = silent_ok = blindness_ok = enum_ok = True
    for ctx in contexts:
        sid, agent = ctx.sol.swarm_id, ctx.agent
        enum_ok = enum_ok and ctx.solver_recovered_ok

        # 1 solver_opening_guess released by both
        if ctx.solver_recovered is None:
            blind_ok = False
        else:
            for dn in ("nongeometric", "geometric_verbose"):
                d = _make_detector(dn, ctx, one_shot=True, strikes=1)
                blind_ok = blind_ok and d.submit(
                    Submission(sid, agent, ctx.solver_recovered, "solver_opening_guess")
                ).released

        # 2 random wrong piece caught by both
        cw = make_candidate(ctx, "random_wrong_piece", random.Random(0))
        if cw is not None:
            for dn in ("nongeometric", "geometric_verbose"):
                d = _make_detector(dn, ctx, one_shot=True, strikes=1)
                r = d.submit(Submission(sid, agent, cw, "random_wrong_piece"))
                catch_ok = catch_ok and (r.blocked and not r.released)

        # 3 legit releases in both geometric variants without a false flag
        for dn in ("geometric_verbose", "geometric_decoy"):
            d = _make_detector(dn, ctx, one_shot=True, strikes=1)
            r = d.submit(Submission(sid, agent, ctx.true_piece, "legit_true_piece"))
            legit_ok = legit_ok and r.released and not r.flagged

        # 4 silent geometric: reason_bits 0 and a baseline reason
        cs = make_candidate(ctx, "random_wrong_piece", random.Random(1))
        if cs is not None:
            d = _make_detector("geometric_silent", ctx, one_shot=True, strikes=1)
            r = d.submit(Submission(sid, agent, cs, "random_wrong_piece"))
            silent_ok = silent_ok and r.reason_bits == 0.0 and r.reason in _BASELINE_REASONS

        # 6 attack_class blindness: same candidate, different label -> identical result
        cb = make_candidate(ctx, "random_wrong_piece", random.Random(2))
        if cb is not None:
            d1 = _make_detector("geometric_verbose", ctx, one_shot=True, strikes=1)
            d2 = _make_detector("geometric_verbose", ctx, one_shot=True, strikes=1)
            r1 = d1.submit(Submission(sid, agent, cb, "random_wrong_piece"))
            r2 = d2.submit(Submission(sid, agent, cb, "GARBAGE_LABEL_xyz"))
            blindness_ok = blindness_ok and (
                r1.released == r2.released and r1.blocked == r2.blocked
                and r1.reason == r2.reason and r1.flagged == r2.flagged
            )

    return {
        "valid": all([blind_ok, catch_ok, legit_ok, silent_ok, blindness_ok, enum_ok]),
        "blindness_release": blind_ok,         # solver guess released by both
        "catch_floor": catch_ok,               # random wrong caught by both
        "legit_no_false_positive": legit_ok,
        "silent_reason_isolated": silent_ok,
        "attack_class_blind": blindness_ok,
        "enumerator_trustworthy": enum_ok,     # ground-truth solver recovered the true piece
    }


def run_keystone(
    *,
    n: int = 3,
    k: int = 4,
    seeds: int = 12,
    strikes_probe: int = 5,
    trials: int = 4000,
    seed_base: int = 5000,
    budget: tuple[float, int] = (5.0, 3_000_000),
) -> dict:
    contexts = build_contexts(n=n, k=k, seeds=seeds, seed_base=seed_base, budget=budget)
    matrix = _attack_matrix(contexts, seed_base)

    false_positive_rate = {
        dn: matrix["legit_true_piece"]["detectors"][dn]["flag_rate"] for dn in DETECTOR_NAMES
    }
    fp_nongeo = false_positive_rate["nongeometric"]["rate"]
    fp_delta = max(false_positive_rate[gv]["rate"] for gv in _GEO_VARIANTS) - fp_nongeo

    catches_more = []
    for ac in ATTACK_CLASSES:
        base = matrix[ac]["detectors"]["nongeometric"]["detection"]["rate"]
        for gv in _GEO_VARIANTS:
            if matrix[ac]["detectors"][gv]["detection"]["rate"] > base + 1e-9:
                catches_more.append({"attack_class": ac, "detector": gv})

    leakage = _leakage(n=n, k=k, seeds=seeds, seed_base=seed_base, trials=trials)
    # The decoy's distinctive signal is the attribution label (not flag_rate, which is
    # 1.0 on any commitment-caught piece). Legit traffic must never be attributed.
    decoy_attribution = {
        "true_positive_on_attacker": matrix["decoy_consistent_wrong"]["detectors"]["geometric_decoy"]["attribution_rate"],
        "false_attribution_on_legit": matrix["legit_true_piece"]["detectors"]["geometric_decoy"]["attribution_rate"],
        "constructible": matrix["decoy_consistent_wrong"]["constructible"],
        "note": "attribution adds provenance on an already-caught attack; it does not raise detection",
    }

    return {
        "config": {"n": n, "k": k, "seeds": seeds, "strikes_probe": strikes_probe, "seed_base": seed_base},
        "positive_controls": positive_controls(contexts),
        "matrix": matrix,
        "false_positive_rate": false_positive_rate,
        "probing": _probing(contexts, strikes=strikes_probe),
        "leakage": leakage,
        "decoy_attribution": decoy_attribution,
        "rollup": {
            "geometric_matches_nongeometric_on_all_attacks": len(catches_more) == 0,
            "attacks_where_geometric_catches_more": catches_more,
            "geometry_marginal_detection_advantage_count": len(catches_more),
            "geometry_marginal_leakage_bits": leakage["geometric_verbose"].get("max_leak_bits") or 0.0,
            "false_positive_delta": fp_delta,
        },
    }
