"""Build a hidden solution, then derive lossy public views (hidden solution first)."""

from __future__ import annotations

import random

from spatial_swarm.spatial_lab import commit as C
from spatial_swarm.spatial_lab.shapes import generate_partitioned
from spatial_swarm.spatial_puzzle.generators.polycube import (
    connector_histogram,
    has_cavity,
    is_asymmetric,
    topology_band,
)
from spatial_swarm.spatial_puzzle.generators.visibility import HiddenSolution, PublicView


def build_hidden_solution(
    rng: random.Random,
    *,
    n: int,
    k: int,
    swarm_id: str,
    repr_name: str = "ADV",
    alphabet_size: int = 4,
    topo_bucket: int = 2,
    mode: str = "grown",
    require_asymmetric: bool = False,  # best-effort; recorded as metadata, not forced (hard at small k)
    max_attempts: int = 200,
) -> HiddenSolution:
    target = pieces = None
    for _ in range(max_attempts):
        target, pieces = generate_partitioned(rng, n, k, mode)
        if not require_asymmetric or all(is_asymmetric(p) for p in pieces.values()):
            break
    commitments = {aid: C.commit(swarm_id, aid, repr_name, p) for aid, p in pieces.items()}
    return HiddenSolution(
        repr_name=repr_name, swarm_id=swarm_id, n=n, k=k, target=frozenset(target),
        pieces={a: frozenset(p) for a, p in pieces.items()}, commitments=commitments,
        alphabet_size=alphabet_size, topo_bucket=topo_bucket,
        asymmetric={a: is_asymmetric(p) for a, p in pieces.items()},
        cavity={a: has_cavity(p) for a, p in pieces.items()},
    )


def derive_public_view(
    sol: HiddenSolution,
    agent: str,
    *,
    shape: bool,
    revealed_count: int,
    connector: bool,
    topology: bool,
) -> PublicView:
    others = [a for a in sol.agent_ids() if a != agent]
    revealed = {a: sol.pieces[a] for a in others[:revealed_count]}
    return PublicView(
        repr_name=sol.repr_name,
        swarm_id=sol.swarm_id,
        k=sol.k,
        agent=agent,
        commitment=sol.commitments[agent],
        outer_shape=sol.target if shape else None,
        revealed_pieces=revealed,
        connector_hist=(
            connector_histogram(sol.pieces[agent], sol.target, sol.alphabet_size) if connector else None
        ),
        topology_band_value=topology_band(sol.pieces[agent], sol.topo_bucket) if topology else None,
        alphabet_size=sol.alphabet_size,
        topo_bucket=sol.topo_bucket,
    )
