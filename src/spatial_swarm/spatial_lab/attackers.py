"""Attackers for the two lab modes, plus the (pluggable) LLM hook.

Every attacker returns a uniform AttackOutcome. The recovered secret is used only
in-lab to compute reconstruction error against ground truth; it is never put in
the loggable view. The LLM hook stores raw model output verbatim and reports
`status: not_run` when no provider is configured.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Callable, Optional

from spatial_swarm.spatial_lab import commit as C
from spatial_swarm.spatial_lab import metrics3d
from spatial_swarm.spatial_lab.pose import apply_pose, inverse_pose, pose_space_size, random_pose
from spatial_swarm.spatial_lab.representations import Swarm
from spatial_swarm.spatial_lab.solvers import assembly_search as A
from spatial_swarm.spatial_lab.solvers import registration as G
from spatial_swarm.spatial_lab.solvers.base import Budget, SolverResult


@dataclass
class AttackOutcome:
    attacker: str
    found: bool
    nodes: int
    guesses: int
    wall_seconds: float
    budget_hit: bool
    pose_space_size: Optional[int] = None
    consistent_candidates: Optional[int] = None
    reconstruction: Optional[dict] = None
    secret_leaked: bool = False
    detail: dict = field(default_factory=dict)

    def public_dict(self) -> dict:
        return {
            "attacker": self.attacker,
            "found": self.found,
            "nodes": self.nodes,
            "guesses": self.guesses,
            "wall_seconds": self.wall_seconds,
            "budget_hit": self.budget_hit,
            "pose_space_size": self.pose_space_size,
            "consistent_candidates": self.consistent_candidates,
            "reconstruction": self.reconstruction,
            "secret_leaked": self.secret_leaked,
            "detail": self.detail,
        }


def _recon(recovered, truth) -> Optional[dict]:
    if recovered is None:
        return None
    return metrics3d.reconstruction_error(recovered, truth)


def _from_solver(attacker: str, res: SolverResult, truth) -> AttackOutcome:
    return AttackOutcome(
        attacker=attacker,
        found=res.found,
        nodes=res.nodes_expanded,
        guesses=res.guesses,
        wall_seconds=res.wall_seconds,
        budget_hit=res.budget_hit,
        pose_space_size=res.pose_space_size,
        consistent_candidates=res.consistent_candidates,
        reconstruction=_recon(res.recovered, truth),
    )


# --------------------------------------------------------------------------- #
# Lab A (unknown-pose registration)
# --------------------------------------------------------------------------- #


def lab_a_registration(sw: Swarm, agent: str, observations, bound: int, budget: Budget) -> AttackOutcome:
    res = G.solve_exhaustive(
        observations=observations, commitment=sw.commitments[agent], swarm_id=sw.swarm_id,
        agent_id=agent, repr_name=sw.repr_name, bound=bound, budget=budget,
    )
    return _from_solver("registration_exhaustive", res, sw.pieces[agent])


def lab_a_local(sw: Swarm, agent: str, observations, window: int, budget: Budget) -> AttackOutcome:
    res = G.solve_local_window(
        observations=observations, commitment=sw.commitments[agent], swarm_id=sw.swarm_id,
        agent_id=agent, repr_name=sw.repr_name, window=window, budget=budget,
    )
    return _from_solver("registration_local", res, sw.pieces[agent])


def lab_a_random_pose(sw: Swarm, agent: str, observations, bound: int, budget: Budget, seed: int) -> AttackOutcome:
    budget.reset()
    rng = random.Random(seed)
    o1 = observations[0]
    nodes = 0
    while not budget.tripped(nodes):
        nodes += 1
        cand = apply_pose(inverse_pose(random_pose(rng, bound)), o1)
        if C.opens(sw.commitments[agent], sw.swarm_id, agent, sw.repr_name, cand):
            return AttackOutcome("random_pose", True, nodes, nodes, budget.elapsed(), False,
                                 pose_space_size=pose_space_size(bound),
                                 reconstruction=_recon(cand, sw.pieces[agent]))
    return AttackOutcome("random_pose", False, nodes, nodes, budget.elapsed(), True,
                         pose_space_size=pose_space_size(bound))


def lab_a_neighbor_copy(sw: Swarm, agent: str, bound: int, budget: Budget) -> AttackOutcome:
    others = [a for a in sw.agent_ids() if a != agent]
    neighbor = sw.pieces[others[0]]
    res = G.solve_exhaustive(
        observations=[frozenset(neighbor)], commitment=sw.commitments[agent], swarm_id=sw.swarm_id,
        agent_id=agent, repr_name=sw.repr_name, bound=bound, budget=budget,
    )
    return _from_solver("neighbor_copy", res, sw.pieces[agent])


# --------------------------------------------------------------------------- #
# Lab B (assembly constraint-search)
# --------------------------------------------------------------------------- #


def _region(sw: Swarm, agent: str, revealed_count: int) -> frozenset:
    others = [a for a in sw.agent_ids() if a != agent]
    revealed = frozenset().union(
        *[sw.pieces[a] for a in others[:revealed_count]]
    ) if revealed_count else frozenset()
    return frozenset(sw.target) - revealed


def lab_b_assembly(sw: Swarm, agent: str, revealed_count: int, budget: Budget, exact: bool) -> AttackOutcome:
    region = _region(sw, agent, revealed_count)
    res = A.solve_backtrack(
        target=sw.target, region=region, k=sw.k, commitment=sw.commitments[agent],
        swarm_id=sw.swarm_id, agent_id=agent, repr_name=sw.repr_name,
        required_connector=sw.public.get("connectors", {}).get(agent),
        required_topology=(tuple(sw.public["topology"][agent]) if "topology" in sw.public else None),
        budget=budget, exact=exact, require_connected=sw.repr_name != "R1",
    )
    out = _from_solver("assembly_backtrack", res, sw.pieces[agent])
    out.detail = {"revealed_others": revealed_count, "region_size": len(region)}
    return out


def lab_b_neighbor_copy(sw: Swarm, agent: str) -> AttackOutcome:
    others = [a for a in sw.agent_ids() if a != agent]
    candidate = sw.pieces[others[0]]
    found = C.opens(sw.commitments[agent], sw.swarm_id, agent, sw.repr_name, candidate)
    return AttackOutcome("neighbor_copy", found, 1, 1, 0.0, False,
                         reconstruction=_recon(candidate, sw.pieces[agent]))


# --------------------------------------------------------------------------- #
# LLM hook (pluggable; raw output stored verbatim; not_run without a provider)
# --------------------------------------------------------------------------- #


@dataclass
class LLMResponse:
    items: list
    raw_output: str
    model: str
    provider: str = "external"


LLMProvider = Callable[[dict], LLMResponse]


def public_observation(sw: Swarm, agent: str, observations: Optional[list]) -> dict:
    """The attacker-visible information handed to a model (no raw secret)."""

    obs = {
        "repr": sw.repr_name,
        "k": sw.k,
        "commitment": sw.commitments[agent],
        "public": sw.public,
    }
    if observations is not None:
        obs["observations"] = [sorted(list(c) for c in view) for view in observations]
    return obs


def llm_attacker(sw: Swarm, agent: str, observations, provider: Optional[LLMProvider]) -> AttackOutcome:
    view = public_observation(sw, agent, observations)
    if provider is None:
        return AttackOutcome("llm", False, 0, 0, 0.0, False, detail={"status": "not_run"})
    resp = provider(view)
    candidate = frozenset(tuple(x) if isinstance(x, list) else x for x in resp.items)
    found = C.opens(sw.commitments[agent], sw.swarm_id, agent, sw.repr_name, candidate)
    return AttackOutcome(
        "llm", found, 1, 1, 0.0, False,
        reconstruction=_recon(candidate, sw.pieces[agent]),
        detail={
            "status": "ran",
            "model": resp.model,
            "provider": resp.provider,
            "raw_output": resp.raw_output,  # verbatim, never rewritten
        },
    )
