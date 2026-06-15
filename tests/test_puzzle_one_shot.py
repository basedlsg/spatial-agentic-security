"""One-shot failure policy and query-attacker models."""

from __future__ import annotations

import math

from spatial_swarm.spatial_lab import commit as C
from spatial_swarm.spatial_puzzle.enclave import query_attacker as Q
from spatial_swarm.spatial_puzzle.enclave.failure_policy import SwarmLifecycle, SwarmState

PIECE = frozenset({(0, 0, 0), (1, 0, 0)})
COMMIT = C.commit("s", "agent_001", "P", PIECE)


def _opener():
    return lambda cand: C.opens(COMMIT, "s", "agent_001", "P", cand)


def test_correct_proof_releases():
    lc = SwarmLifecycle("s", _opener(), one_shot=True, sidecars={"a": "secret"})
    out = lc.submit_proof(PIECE)
    assert out.released and lc.state is SwarmState.ALIVE and not out.zeroized


def test_wrong_proof_one_shot_destroys_and_blocks_retry():
    lc = SwarmLifecycle("s", _opener(), one_shot=True, sidecars={"a": "secret"})
    out = lc.submit_proof(frozenset({(9, 9, 9), (8, 8, 8)}))
    assert out.blocked and out.state is SwarmState.DEAD
    assert out.sidecars_wiped and out.zeroized and not out.retry_allowed
    assert lc.sidecars == {} and lc.zeroized
    # a second attempt (even the correct one) is refused
    second = lc.submit_proof(PIECE)
    assert second.blocked and not second.released and second.reason == "swarm_dead"


def test_retries_mode_allows_retry():
    lc = SwarmLifecycle("s", _opener(), one_shot=False, sidecars={"a": "secret"})
    out = lc.submit_proof(frozenset({(9, 9, 9), (8, 8, 8)}))
    assert out.retry_allowed and lc.state is SwarmState.ALIVE and not out.zeroized


def test_blind_one_shot_probability_matches_inverse_residual():
    m = Q.measure_one_shot_recovery(50, trials=4000, seed=1)
    assert m["analytic_recovery_prob"] == 1 / 50
    assert abs(m["recovery_rate"] - 0.02) < 0.02  # near 1/50
    assert m["recovery_rate_ci95"]["low"] <= m["recovery_rate"] <= m["recovery_rate_ci95"]["high"]


def test_larger_residual_is_safer_one_shot():
    small = Q.measure_one_shot_recovery(4, trials=2000, seed=2)["recovery_rate"]
    large = Q.measure_one_shot_recovery(400, trials=2000, seed=2)["recovery_rate"]
    assert large < small  # max-entropy (random ceiling) is safer under one-shot


def test_candidate_elimination_and_oracle():
    # retries: recover within R submissions
    run = Q.candidate_elimination(10, true_index=7, one_shot=True)
    assert not run.recovered and run.destroyed  # one-shot, true not first -> destroyed
    run2 = Q.candidate_elimination(10, true_index=0, one_shot=True)
    assert run2.recovered
    retry = Q.candidate_elimination(10, true_index=7, one_shot=False)
    assert retry.recovered and retry.queries_before_recovery == 8
    # a non-destructive oracle defeats one-shot in ~log2(R) queries
    orc = Q.binary_search_oracle(64)
    assert orc.recovered and not orc.destroyed
    assert orc.queries_before_recovery == math.ceil(math.log2(64)) + 1
