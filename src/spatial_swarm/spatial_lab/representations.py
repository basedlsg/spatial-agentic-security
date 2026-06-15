"""The representation ladder R0..R4 (secret format), commitment held fixed.

R0 random_bytes  : k distinct ints, independent per agent (no shared object) -- control
R1 points3d      : k points of a shared F_p^3 cloud (no adjacency)
R2 voxel_solid   : connected k-voxel piece of a shared object; public = outer shape
R3 voxel_connectors : R2 + published connector signature per piece
R4 voxel_topology   : R3 + published topology signature per piece

The commitment is over the piece's absolute items, identical construction across
representations (see commit.py). Rotation lives in the solver/pose layer, not the
commitment, so the registration search is non-trivial.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Optional

from spatial_swarm.spatial_lab import commit as C
from spatial_swarm.spatial_lab import shapes as S
from spatial_swarm.spatial_lab.entropy import EntropyAccount, log2_comb

REPRESENTATIONS: tuple[str, ...] = ("R0", "R1", "R2", "R3", "R4")
_VOXEL_REPRS = frozenset({"R2", "R3", "R4"})


@dataclass
class Swarm:
    repr_name: str
    n: int
    k: int
    swarm_id: str
    pieces: dict[str, frozenset]              # secret items per agent
    commitments: dict[str, str]
    target: Optional[frozenset] = None        # shared object (R1 cloud / R2-R4 voxel object)
    public: dict = field(default_factory=dict)  # per-repr public constraints
    params: dict = field(default_factory=dict)

    def agent_ids(self) -> list[str]:
        return sorted(self.pieces)


def _agent_id(i: int) -> str:
    return f"agent_{i:03d}"


def build_swarm(repr_name: str, rng: random.Random, n: int, k: int, params: dict, swarm_id: str) -> Swarm:
    if repr_name == "R0":
        m = params["m"]
        pieces = {}
        for i in range(n):
            s: set[int] = set()
            while len(s) < k:
                s.add(rng.randrange(m))
            pieces[_agent_id(i + 1)] = frozenset(s)
        return _finish(repr_name, n, k, swarm_id, pieces, None, {}, params)

    if repr_name == "R1":
        p = params["p"]
        cloud: set = set()
        while len(cloud) < n * k:
            cloud.add((rng.randrange(p), rng.randrange(p), rng.randrange(p)))
        ordered = sorted(cloud)
        pieces = {_agent_id(i + 1): frozenset(ordered[i * k:(i + 1) * k]) for i in range(n)}
        public = {"cloud": [list(c) for c in ordered]}
        return _finish(repr_name, n, k, swarm_id, pieces, frozenset(cloud), public, params)

    if repr_name in _VOXEL_REPRS:
        mode = params.get("mode", "grown")
        target, pieces = S.generate_partitioned(rng, n, k, mode)
        public: dict = {"target": [list(c) for c in sorted(target)]}
        if repr_name in ("R3", "R4"):
            public["connectors"] = {
                aid: S.connector_signature(piece, target) for aid, piece in pieces.items()
            }
        if repr_name == "R4":
            public["topology"] = {
                aid: list(S.topology_signature(piece)) for aid, piece in pieces.items()
            }
        return _finish(repr_name, n, k, swarm_id, pieces, target, public, params)

    raise ValueError(f"unknown representation {repr_name!r}")


def _finish(repr_name, n, k, swarm_id, pieces, target, public, params) -> Swarm:
    commitments = {
        aid: C.commit(swarm_id, aid, repr_name, items) for aid, items in pieces.items()
    }
    return Swarm(
        repr_name=repr_name,
        n=n,
        k=k,
        swarm_id=swarm_id,
        pieces=pieces,
        commitments=commitments,
        target=target,
        public=public,
        params=params,
    )


def commitment_only_entropy(repr_name: str, n: int, k: int, params: dict) -> EntropyAccount:
    """log2 of the no-observation brute-force secret space for one piece."""

    if repr_name == "R0":
        return EntropyAccount("R0", log2_comb(params["m"], k), f"C(M={params['m']},k={k})", False)
    if repr_name == "R1":
        p = params["p"]
        return EntropyAccount("R1", log2_comb(p**3, k), f"C(p^3={p**3},k={k})", False)
    if repr_name in _VOXEL_REPRS:
        # Upper bound: any k-subset of a bounding cube big enough to hold the object.
        side = 1
        while side**3 < n * k:
            side += 1
        vol = side**3
        return EntropyAccount(
            repr_name, log2_comb(vol, k), f"C(bbox_vol={vol},k={k}) upper bound", True
        )
    raise ValueError(f"unknown representation {repr_name!r}")
