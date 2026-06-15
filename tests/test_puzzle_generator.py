"""Adversarial generator: lossy clues, rejection gates, acceptance yield."""

from __future__ import annotations

import random

from spatial_swarm.spatial_lab import commit as C
from spatial_swarm.spatial_lab.solvers.base import Budget
from spatial_swarm.spatial_puzzle.generators import build, rejection
from spatial_swarm.spatial_puzzle.generators.visibility import clue_predicate_for, region_for


def _sol(seed=3, n=3, k=4, alphabet_size=4):
    return build.build_hidden_solution(
        random.Random(seed), n=n, k=k, swarm_id="s", alphabet_size=alphabet_size
    )


def test_pieces_open_their_commitments_and_tile():
    sol = _sol()
    union = set()
    for aid, piece in sol.pieces.items():
        assert C.opens(sol.commitments[aid], sol.swarm_id, aid, sol.repr_name, piece)
        union |= set(piece)
    assert union == set(sol.target)


def test_true_piece_satisfies_its_own_public_view():
    sol = _sol()
    agent = sol.agent_ids()[1]
    view = build.derive_public_view(sol, agent, shape=True, revealed_count=0, connector=True, topology=True)
    region = region_for(view)
    assert sol.pieces[agent] <= region
    assert clue_predicate_for(view)(sol.pieces[agent])  # control: the true piece passes


def test_public_view_holds_no_raw_target_piece():
    sol = _sol()
    agent = sol.agent_ids()[1]
    view = build.derive_public_view(sol, agent, shape=True, revealed_count=0, connector=True, topology=True)
    # the target agent's own piece is never directly in the view (only lossy projections)
    assert agent not in view.revealed_pieces
    assert isinstance(view.connector_hist, tuple)
    assert isinstance(view.topology_band_value, tuple)


def test_large_alphabet_connector_uniquely_identifies_and_is_rejected():
    # alphabet ~ exact signature -> connector histogram pins the piece (the prior leak)
    sol = _sol(alphabet_size=64)
    verdict = rejection.evaluate_candidate(sol, ambiguity_target=2, budget_factory=lambda: Budget(10.0, 2_000_000))
    assert verdict.per_clue_residual["connector_only"] == 1
    assert "unique_by_connector_only" in verdict.reasons
    assert not verdict.accepted


def test_coarse_alphabet_is_less_identifying_than_fine():
    coarse = rejection.evaluate_candidate(_sol(alphabet_size=2), ambiguity_target=2, budget_factory=lambda: Budget(10.0, 2_000_000))
    fine = rejection.evaluate_candidate(_sol(alphabet_size=64), ambiguity_target=2, budget_factory=lambda: Budget(10.0, 2_000_000))
    # same seed/shape; coarser connector alphabet leaves >= as many candidates as the fine one
    assert (coarse.per_clue_residual["connector_only"] or 0) >= (fine.per_clue_residual["connector_only"] or 0)


def test_evaluate_candidate_controls_pass():
    verdict = rejection.evaluate_candidate(_sol(), ambiguity_target=2, budget_factory=lambda: Budget(10.0, 2_000_000))
    assert verdict.controls_pass  # the true piece is always within the residual


def test_generate_accepted_reports_yield_and_reasons():
    sol, stats = rejection.generate_accepted(
        random.Random(1), n=3, k=4, swarm_id="g", ambiguity_target=3, max_generation_attempts=40
    )
    assert set(stats) >= {"attempts", "accepted", "acceptance_yield", "reason_histogram"}
    assert stats["attempts"] >= 1
    if stats["accepted"]:
        assert sol is not None and stats["accepted_residual"] >= 3
    else:
        # a near-zero yield is a legitimate, recorded outcome (structure collapses residual)
        assert sum(stats["reason_histogram"].values()) >= 1
