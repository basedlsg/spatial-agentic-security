"""Detector keystone: strike counter, two detectors, attack suite, gating controls, roll-up."""

from __future__ import annotations

import json
import math
import random

from spatial_swarm.experiments.redaction import scan_text
from spatial_swarm.spatial_lab import commit as C
from spatial_swarm.spatial_puzzle.detector import metrics_detector as M
from spatial_swarm.spatial_puzzle.detector.attacks import build_attack_context, make_candidate
from spatial_swarm.spatial_puzzle.detector.base import Submission
from spatial_swarm.spatial_puzzle.detector.geometric import GeometricDetector
from spatial_swarm.spatial_puzzle.detector.nongeometric import NonGeometricTripwire
from spatial_swarm.spatial_puzzle.enclave.failure_policy import SwarmLifecycle, SwarmState
from spatial_swarm.spatial_puzzle.generators.build import build_hidden_solution

PIECE = frozenset({(0, 0, 0), (1, 0, 0)})
COMMIT = C.commit("s", "a", "P", PIECE)
WRONG = frozenset({(9, 9, 9), (8, 9, 9)})


def _opener():
    return lambda cand: C.opens(COMMIT, "s", "a", "P", cand)


# ---- Step 1: strike counter --------------------------------------------------

def test_strikes_default_one_is_legacy_one_shot():
    lc = SwarmLifecycle("s", _opener(), one_shot=True)  # strikes defaults to 1
    out = lc.submit_proof(WRONG)
    assert out.state is SwarmState.DEAD and out.zeroized and out.reason == "wrong_proof_destroyed"


def test_strikes_tolerates_then_dies_on_nth():
    lc = SwarmLifecycle("s", _opener(), one_shot=True, strikes=3)
    a = lc.submit_proof(WRONG)
    b = lc.submit_proof(WRONG)
    assert a.state is SwarmState.ALIVE and b.state is SwarmState.ALIVE  # tolerated
    c = lc.submit_proof(WRONG)
    assert c.state is SwarmState.DEAD and c.reason == "wrong_proof_destroyed"
    # the correct proof before the 3rd strike would still release
    lc2 = SwarmLifecycle("s", _opener(), one_shot=True, strikes=3)
    lc2.submit_proof(WRONG)
    assert lc2.submit_proof(PIECE).released


# ---- helpers -----------------------------------------------------------------

def _ctx(seed=5000):
    sol = build_hidden_solution(random.Random(seed), n=3, k=4, swarm_id=f"det-{seed}")
    return build_attack_context(sol)


def _ctx_with_decoy():
    for seed in range(5000, 5050):
        ctx = _ctx(seed)
        if ctx.decoy_hist is not None and make_candidate(ctx, "decoy_consistent_wrong", random.Random(0)):
            return ctx
    raise AssertionError("no seed produced a constructible decoy")


# ---- Step 2: detectors -------------------------------------------------------

def test_nongeometric_catches_wrong_and_releases_legit():
    ctx = _ctx()

    def sub(cand):
        return Submission(ctx.sol.swarm_id, ctx.agent, cand, "x")

    d = NonGeometricTripwire(ctx.sol)
    assert d.submit(sub(ctx.true_piece)).released
    d2 = NonGeometricTripwire(ctx.sol)
    r = d2.submit(sub(ctx.wrong_subsets[0]))
    assert r.blocked and not r.released and r.reason_bits == 0.0


def test_solver_opening_guess_released_by_both():
    ctx = _ctx()
    assert ctx.solver_recovered is not None and ctx.solver_recovered_ok
    sub = Submission(ctx.sol.swarm_id, ctx.agent, ctx.solver_recovered, "solver_opening_guess")
    assert NonGeometricTripwire(ctx.sol).submit(sub).released
    assert GeometricDetector(ctx.sol, reason_mode="verbose").submit(sub).released


def test_geometric_silent_reason_isolated_verbose_discriminates():
    ctx = _ctx()
    out_of_region = frozenset({(99, 99, 99), (99, 99, 98), (99, 99, 97), (99, 99, 96)})
    sub = Submission(ctx.sol.swarm_id, ctx.agent, out_of_region, "x")
    silent = GeometricDetector(ctx.sol, reason_mode="silent").submit(sub)
    assert silent.reason_bits == 0.0 and silent.reason in ("wrong_proof_destroyed", "wrong_proof_retry")
    verbose = GeometricDetector(ctx.sol, reason_mode="verbose").submit(sub)
    assert verbose.reason == "wrong_shape_membership"
    assert verbose.reason_bits == math.log2(4)


def test_attack_class_label_is_ignored():
    ctx = _ctx()
    cand = ctx.wrong_subsets[0]
    r1 = GeometricDetector(ctx.sol, reason_mode="verbose").submit(
        Submission(ctx.sol.swarm_id, ctx.agent, cand, "random_wrong_piece")
    )
    r2 = GeometricDetector(ctx.sol, reason_mode="verbose").submit(
        Submission(ctx.sol.swarm_id, ctx.agent, cand, "GARBAGE")
    )
    assert (r1.released, r1.blocked, r1.reason, r1.flagged) == (r2.released, r2.blocked, r2.reason, r2.flagged)


def test_decoy_attributes_attacker_not_legit():
    ctx = _ctx_with_decoy()
    d = GeometricDetector(ctx.sol, reason_mode="silent", decoy_hist=ctx.decoy_hist)
    atk = make_candidate(ctx, "decoy_consistent_wrong", random.Random(0))
    r_atk = d.submit(Submission(ctx.sol.swarm_id, ctx.agent, atk, "decoy_consistent_wrong"))
    assert r_atk.attribution == "decoy_consistent"
    d2 = GeometricDetector(ctx.sol, reason_mode="silent", decoy_hist=ctx.decoy_hist)
    r_legit = d2.submit(Submission(ctx.sol.swarm_id, ctx.agent, ctx.true_piece, "legit_true_piece"))
    assert r_legit.released and r_legit.attribution is None


# ---- Steps 4-5: keystone roll-up + gating controls ---------------------------

def test_keystone_rollup_and_controls():
    r = M.run_keystone(n=3, k=4, seeds=4, strikes_probe=4, trials=500, seed_base=5000)
    assert r["positive_controls"]["valid"] is True
    roll = r["rollup"]
    # geometry catches nothing the tripwire misses
    assert roll["geometry_marginal_detection_advantage_count"] == 0
    assert roll["geometric_matches_nongeometric_on_all_attacks"] is True
    # no detector flags legit traffic
    assert roll["false_positive_delta"] == 0.0
    # the verbose detector leaks strictly more than the baseline (a fit/no-fit oracle)
    assert roll["geometry_marginal_leakage_bits"] > 0.0
    # both detectors are equally blind to a commitment-opening guess
    assert r["matrix"]["solver_opening_guess"]["detectors"]["geometric_verbose"]["detection"]["rate"] == 0.0
    assert r["matrix"]["solver_opening_guess"]["detectors"]["nongeometric"]["detection"]["rate"] == 0.0
    # decoy attributes attackers, never legit
    da = r["decoy_attribution"]
    assert da["false_attribution_on_legit"]["rate"] == 0.0


def test_probing_identical_across_detectors():
    r = M.run_keystone(n=3, k=4, seeds=4, strikes_probe=5, trials=200, seed_base=5000)
    p = r["probing"]
    # both detect (flag) on the first wrong proof and shut down on the same strike
    assert p["nongeometric"]["queries_to_first_flag"]["p50"] == p["geometric_verbose"]["queries_to_first_flag"]["p50"]
    assert p["nongeometric"]["queries_to_shutdown"]["p50"] == p["geometric_verbose"]["queries_to_shutdown"]["p50"]


def test_metrics_serialize_redaction_clean():
    r = M.run_keystone(n=3, k=4, seeds=3, strikes_probe=3, trials=200, seed_base=5000)
    assert scan_text(json.dumps(r)) == []
