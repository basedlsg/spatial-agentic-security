"""Positive controls: instances the solvers MUST solve.

These gate the experiment. If a control fails, the run is invalid -- it means a
solver is broken, so a "0% attacker success" elsewhere could be a bug rather than
a property of the representation.

planted_pose (Lab A): an observation taken at the identity pose, so the true piece
is reachable at rotation=identity, translation=0.
planted_piece (Lab B): every other piece revealed, so the region equals the target
piece exactly and the search must return it.
"""

from __future__ import annotations

import random

from spatial_swarm.spatial_lab import representations as Rep
from spatial_swarm.spatial_lab.solvers import assembly_search, registration
from spatial_swarm.spatial_lab.solvers.base import Budget

# Lab A applies to representations with a spatial pose (R1 points and R2-R4 voxels).
LAB_A_REPRS = ("R1", "R2", "R3", "R4")
# Lab B applies to shared-object representations (R1 cloud, R2-R4 voxels).
LAB_B_REPRS = ("R1", "R2", "R3", "R4")


def _middle_agent(sw: Rep.Swarm) -> str:
    ids = sw.agent_ids()
    return ids[len(ids) // 2]


def check_planted_pose(repr_name, rng, n, k, params, swarm_id, bound, budget) -> bool:
    sw = Rep.build_swarm(repr_name, rng, n, k, params, swarm_id)
    agent = _middle_agent(sw)
    observations = [frozenset(sw.pieces[agent])]  # identity pose: O == P
    res = registration.solve_exhaustive(
        observations=observations,
        commitment=sw.commitments[agent],
        swarm_id=sw.swarm_id,
        agent_id=agent,
        repr_name=repr_name,
        bound=bound,
        budget=budget,
    )
    return res.found and not res.budget_hit


def check_planted_piece(repr_name, rng, n, k, params, swarm_id, budget) -> bool:
    sw = Rep.build_swarm(repr_name, rng, n, k, params, swarm_id)
    agent = _middle_agent(sw)
    others = frozenset().union(
        *[p for a, p in sw.pieces.items() if a != agent]
    ) if len(sw.pieces) > 1 else frozenset()
    region = frozenset(sw.target) - others   # exactly the target piece
    res = assembly_search.solve_backtrack(
        target=sw.target,
        region=region,
        k=k,
        commitment=sw.commitments[agent],
        swarm_id=sw.swarm_id,
        agent_id=agent,
        repr_name=repr_name,
        required_connector=sw.public.get("connectors", {}).get(agent),
        required_topology=(
            tuple(sw.public["topology"][agent]) if "topology" in sw.public else None
        ),
        budget=budget,
        exact=False,
        require_connected=repr_name != "R1",
    )
    return res.found and not res.budget_hit
