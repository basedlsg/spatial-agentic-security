"""Shared attack suite: one spec per attack class, the SAME candidate fed to both detectors.

Each class is constructed once per hidden solution (an `AttackContext`) so the two
detectors see identical submissions. Provenance is a label only; detectors never read
it. `make_candidate` returns None when a class is not constructible for a given seed
(e.g. no congruent in-region subset, or no decoy-matching wrong subset) -- the caller
records the class as skipped rather than fabricating a non-representative candidate.
"""

from __future__ import annotations

import random
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional

from spatial_swarm.spatial_lab.solvers.assembly_search import connected_subsets
from spatial_swarm.spatial_lab.solvers.base import Budget
from spatial_swarm.spatial_puzzle.generators.polycube import connector_histogram
from spatial_swarm.spatial_puzzle.generators.visibility import HiddenSolution
from spatial_swarm.spatial_puzzle.solvers import graph_iso, pure_enum

# Single-submission attack classes (repeated probing is a sequence, handled in metrics).
ATTACK_CLASSES = (
    "legit_true_piece",
    "random_wrong_piece",
    "stolen_neighbor",
    "congruent_shape",
    "solver_opening_guess",
    "decoy_consistent_wrong",
)

# Ground-truth expectation per class (commitment is the catch floor for both detectors).
RELEASED_EXPECTED = {
    "legit_true_piece": True,
    "solver_opening_guess": True,
    "random_wrong_piece": False,
    "stolen_neighbor": False,
    "congruent_shape": False,
    "decoy_consistent_wrong": False,
}


def spec_for(attack_class: str) -> dict:
    if attack_class not in ATTACK_CLASSES:
        raise ValueError(f"unknown attack_class: {attack_class}")
    return {"attack_class": attack_class, "released_expected": RELEASED_EXPECTED[attack_class]}


def target_agent(sol: HiddenSolution) -> str:
    ids = sol.agent_ids()
    return ids[len(ids) // 2]


@dataclass
class AttackContext:
    sol: HiddenSolution
    agent: str
    true_piece: frozenset
    subsets: list = field(default_factory=list)        # connected k-subsets of the target
    wrong_subsets: list = field(default_factory=list)   # subsets != true_piece
    true_hist: tuple = ()
    decoy_hist: Optional[tuple] = None
    congruent_subset: Optional[frozenset] = None
    solver_recovered: Optional[frozenset] = None
    solver_recovered_ok: bool = False


def _decoy_histogram(sol: HiddenSolution, true_hist: tuple, wrong_subsets: list) -> Optional[tuple]:
    """A connector histogram some wrong subset produces but the true piece does not.

    Published as the honeypot value: a legitimate piece never matches it (no false
    positive), while an attacker who crafts a piece to satisfy the published geometry
    matches it (attribution signal). None if no such histogram exists for this seed.
    """

    counts: Counter = Counter()
    for c in wrong_subsets:
        h = connector_histogram(c, sol.target, sol.alphabet_size)
        if h != true_hist:
            counts[h] += 1
    if not counts:
        return None
    return counts.most_common(1)[0][0]


def build_attack_context(sol: HiddenSolution, *, budget: tuple[float, int] = (5.0, 3_000_000)) -> AttackContext:
    agent = target_agent(sol)
    true_piece = sol.pieces[agent]
    subsets = [frozenset(c) for c in connected_subsets(frozenset(sol.target), sol.k)]
    wrong_subsets = [c for c in subsets if c != true_piece]
    true_hist = connector_histogram(true_piece, sol.target, sol.alphabet_size)
    decoy_hist = _decoy_histogram(sol, true_hist, wrong_subsets)
    congruent = next(
        (c for c in wrong_subsets if graph_iso.pieces_isomorphic(c, true_piece)), None
    )
    res = pure_enum.solve(
        region=sol.target, k=sol.k, commitment=sol.commitments[agent], swarm_id=sol.swarm_id,
        agent_id=agent, repr_name=sol.repr_name, budget=Budget(*budget), mode="recover",
        require_connected=True,
    )
    return AttackContext(
        sol=sol, agent=agent, true_piece=true_piece, subsets=subsets, wrong_subsets=wrong_subsets,
        true_hist=true_hist, decoy_hist=decoy_hist, congruent_subset=congruent,
        solver_recovered=res.recovered, solver_recovered_ok=(res.recovered == true_piece),
    )


def make_candidate(ctx: AttackContext, attack_class: str, rng: random.Random) -> Optional[frozenset]:
    spec_for(attack_class)  # validates / raises on unknown
    if attack_class == "legit_true_piece":
        return ctx.true_piece
    if attack_class == "random_wrong_piece":
        return rng.choice(ctx.wrong_subsets) if ctx.wrong_subsets else None
    if attack_class == "stolen_neighbor":
        others = [p for a, p in ctx.sol.pieces.items() if a != ctx.agent]
        return rng.choice(others) if others else None
    if attack_class == "congruent_shape":
        return ctx.congruent_subset
    if attack_class == "solver_opening_guess":
        return ctx.solver_recovered
    if attack_class == "decoy_consistent_wrong":
        if ctx.decoy_hist is None:
            return None
        matches = [
            c for c in ctx.wrong_subsets
            if connector_histogram(c, ctx.sol.target, ctx.sol.alphabet_size) == ctx.decoy_hist
        ]
        return rng.choice(matches) if matches else None
    return None  # unreachable (spec_for already validated)
