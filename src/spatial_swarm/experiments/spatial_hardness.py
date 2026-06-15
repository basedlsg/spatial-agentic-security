"""Spatial-hardness comparison: random vs 3D secrets, commitment scheme held constant.

Question: holding the commitment scheme fixed, does a 3D-structured secret make
reconstruction of a hidden agent secret harder than a structureless random secret?

This is a research harness, separate from the protocol. It strips the encryption
shield (which, with crypto intact, blocks reconstruction regardless of secret
format -- see the eval-kit control) and measures reconstruction of one agent's
secret under graded public observation, for three secret formats:

  random   : a set of k distinct integers, independent per agent (no shared object)
  points3d : the current scheme -- k distinct points of a shared F_p^3 point cloud
  voxel    : a shared voxel object partitioned into connected k-voxel pieces

Measured: exact-recovery rate, the number of secrets consistent with what is
observed (candidate-space size), and brute-force search cost on small instances.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass
from itertools import combinations
from math import comb

from spatial_swarm.crypto.hashing import sha256_hex

Item = object  # int (random) or (x, y, z) tuple (geometry)


def commit(agent_id: str, secret: frozenset) -> str:
    return sha256_hex({"agent": agent_id, "items": sorted(_as_list(x) for x in secret)})


def _as_list(item):
    return list(item) if isinstance(item, tuple) else item


# --------------------------------------------------------------------------- #
# Swarm generation per scheme
# --------------------------------------------------------------------------- #


@dataclass
class Swarm:
    scheme: str
    target: frozenset | None          # the shared object (None for random)
    pieces: dict[str, frozenset]      # agent_id -> secret
    domain_size: int                  # number of possible secrets (commitment-only)


def _agent_ids(n: int) -> list[str]:
    return [f"agent_{i:03d}" for i in range(1, n + 1)]


def make_random_swarm(rng: random.Random, n: int, k: int, m: int) -> Swarm:
    pieces = {}
    for aid in _agent_ids(n):
        s: set[int] = set()
        while len(s) < k:
            s.add(rng.randrange(m))
        pieces[aid] = frozenset(s)
    return Swarm("random", None, pieces, comb(m, k))


def make_points_swarm(rng: random.Random, n: int, k: int, p: int) -> Swarm:
    total = n * k
    full: set[tuple[int, int, int]] = set()
    while len(full) < total:
        full.add((rng.randrange(p), rng.randrange(p), rng.randrange(p)))
    ordered = sorted(full)
    pieces = {}
    for i, aid in enumerate(_agent_ids(n)):
        pieces[aid] = frozenset(ordered[i * k:(i + 1) * k])
    return Swarm("points3d", frozenset(full), pieces, comb(p**3, k))


def _box_voxels(dims: tuple[int, int, int]) -> list[tuple[int, int, int]]:
    ax, ay, az = dims
    out = []
    for x in range(ax):
        row = range(ay) if x % 2 == 0 else range(ay - 1, -1, -1)  # snake for connectivity
        for y in row:
            col = range(az) if (x + y) % 2 == 0 else range(az - 1, -1, -1)
            for z in col:
                out.append((x, y, z))
    return out


def make_voxel_swarm(rng: random.Random, n: int, k: int, dims: tuple[int, int, int]) -> Swarm:
    voxels = _box_voxels(dims)
    if len(voxels) != n * k:
        raise ValueError(f"box {dims} has {len(voxels)} voxels, need {n*k}")
    pieces = {}
    for i, aid in enumerate(_agent_ids(n)):
        pieces[aid] = frozenset(voxels[i * k:(i + 1) * k])  # contiguous along snake => connected
    grid = dims[0] * dims[1] * dims[2]
    return Swarm("voxel", frozenset(voxels), pieces, comb(grid, k))


# --------------------------------------------------------------------------- #
# Experiment 1: brute-force search cost on small instances
# --------------------------------------------------------------------------- #


def brute_force_search(
    swarm: Swarm, target_agent: str, *, sampler, cap: int, seed: int
) -> dict:
    """Sample candidate secrets and check the commitment, up to `cap` guesses."""

    rng = random.Random(seed)
    truth_commit = commit(target_agent, swarm.pieces[target_agent])
    started = time.perf_counter()
    for guess in range(1, cap + 1):
        candidate = sampler(rng)
        if commit(target_agent, candidate) == truth_commit:
            return {
                "found": True,
                "guesses": guess,
                "seconds": time.perf_counter() - started,
                "domain_size": swarm.domain_size,
            }
    return {
        "found": False,
        "guesses": cap,
        "seconds": time.perf_counter() - started,
        "domain_size": swarm.domain_size,
    }


# --------------------------------------------------------------------------- #
# Experiment 2: assembly-complement reconstruction (attacker has target + others)
# --------------------------------------------------------------------------- #


def assembly_complement_recovery(swarm: Swarm, target_agent: str) -> dict:
    """Attacker observes the shared target and every OTHER agent's piece."""

    others = frozenset().union(
        *[p for a, p in swarm.pieces.items() if a != target_agent]
    ) if len(swarm.pieces) > 1 else frozenset()
    truth = swarm.pieces[target_agent]
    if swarm.target is None:
        # Random scheme: no shared object links the secrets; nothing recovered.
        return {"exact_recovery": False, "candidate_count": swarm.domain_size}
    recovered = swarm.target - others
    return {"exact_recovery": recovered == truth, "candidate_count": 1}


# --------------------------------------------------------------------------- #
# Experiment 3: candidate count as a function of how many other pieces are seen
# --------------------------------------------------------------------------- #


def _connected(voxels: frozenset) -> bool:
    if not voxels:
        return False
    start = next(iter(voxels))
    seen = {start}
    stack = [start]
    while stack:
        x, y, z = stack.pop()
        for dx, dy, dz in ((1, 0, 0), (-1, 0, 0), (0, 1, 0), (0, -1, 0), (0, 0, 1), (0, 0, -1)):
            nb = (x + dx, y + dy, z + dz)
            if nb in voxels and nb not in seen:
                seen.add(nb)
                stack.append(nb)
    return len(seen) == len(voxels)


def candidate_count_partial(swarm: Swarm, target_agent: str, others_seen: int, *, require_connected: bool) -> int:
    """Number of valid k-subsets of the unrevealed region that could be the target piece.

    Attacker observes the shared target and `others_seen` of the other pieces.
    """

    if swarm.target is None:
        return swarm.domain_size  # random: observation gives no constraint
    other_ids = [a for a in swarm.pieces if a != target_agent]
    revealed = frozenset().union(
        *[swarm.pieces[a] for a in other_ids[:others_seen]]
    ) if others_seen else frozenset()
    region = swarm.target - revealed
    k = len(swarm.pieces[target_agent])
    count = 0
    for combo in combinations(sorted(region), k):
        s = frozenset(combo)
        if require_connected and not _connected(s):
            continue
        count += 1
    return count


# --------------------------------------------------------------------------- #
# Top-level runner
# --------------------------------------------------------------------------- #


def run_spatial_hardness(seed: int = 7) -> dict:
    results: dict = {}

    # E1: brute-force search on small instances (k=2 so domains are enumerable).
    e1 = {}
    rnd_small = make_random_swarm(random.Random(seed), 4, 2, 128)
    pts_small = make_points_swarm(random.Random(seed), 4, 2, 5)
    vox_small = make_voxel_swarm(random.Random(seed), 4, 2, (2, 2, 2))
    e1["random_m128_k2"] = brute_force_search(
        rnd_small, "agent_001",
        sampler=lambda r: frozenset(r.sample(range(128), 2)), cap=200_000, seed=seed,
    )
    e1["points_p5_k2"] = brute_force_search(
        pts_small, "agent_001",
        sampler=lambda r: frozenset(
            r.sample([(x, y, z) for x in range(5) for y in range(5) for z in range(5)], 2)
        ),
        cap=200_000, seed=seed,
    )
    box = _box_voxels((2, 2, 2))
    e1["voxel_2x2x2_k2"] = brute_force_search(
        vox_small, "agent_001",
        sampler=lambda r: frozenset(r.sample(box, 2)), cap=200_000, seed=seed,
    )
    # realistic domain sizes (bits), no search run
    e1["realistic_domain_bits"] = {
        "random_m2^32_k16": round(_bits(comb(2**32, 16)), 1),
        "points_p257_k16": round(_bits(comb(257**3, 16)), 1),
        "voxel_16^3_k16": round(_bits(comb(16**3, 16)), 1),
    }
    results["e1_bruteforce"] = e1

    # E2: assembly-complement recovery, averaged over swarms.
    e2 = {scheme: {"exact_recoveries": 0, "trials": 0, "candidate_count": None} for scheme in ("random", "points3d", "voxel")}
    for t in range(20):
        sr = random.Random(seed + t)
        swarms = {
            "random": make_random_swarm(sr, 4, 4, 2**16),
            "points3d": make_points_swarm(sr, 4, 4, 257),
            "voxel": make_voxel_swarm(sr, 4, 4, (4, 2, 2)),
        }
        for scheme, sw in swarms.items():
            out = assembly_complement_recovery(sw, "agent_002")
            e2[scheme]["trials"] += 1
            e2[scheme]["exact_recoveries"] += int(out["exact_recovery"])
            e2[scheme]["candidate_count"] = out["candidate_count"]
    results["e2_assembly_complement"] = e2

    # E3: candidate count vs number of other pieces observed (small voxel + points).
    sr = random.Random(seed)
    vox = make_voxel_swarm(sr, 3, 4, (3, 2, 2))   # 12 voxels, 3 pieces of 4
    pts = make_points_swarm(random.Random(seed), 3, 4, 5)  # 12 points in F_5^3
    rnd = make_random_swarm(random.Random(seed), 3, 4, 2**16)
    e3 = {"voxel_connected": [], "points3d": [], "random": []}
    for j in range(0, 3):  # observe 0,1,2 of the other pieces
        e3["voxel_connected"].append(
            {"others_seen": j, "candidates": candidate_count_partial(vox, "agent_001", j, require_connected=True)}
        )
        e3["points3d"].append(
            {"others_seen": j, "candidates": candidate_count_partial(pts, "agent_001", j, require_connected=False)}
        )
        e3["random"].append(
            {"others_seen": j, "candidates": candidate_count_partial(rnd, "agent_001", j, require_connected=False)}
        )
    results["e3_partial_observation"] = e3

    # E4: does observing one prior-round transformed piece (plaintext) leak it?
    # The protocol's challenge transform is public and invertible.
    from spatial_swarm.geometry.transform import transform_from_challenge

    e4 = {"trials": 0, "exact_recoveries": 0, "observations": 1}
    for t in range(20):
        sw = make_points_swarm(random.Random(seed + t), 4, 16, 257)
        piece = sw.pieces["agent_001"]
        transform = transform_from_challenge(f"prior-round-{t}", 257)
        observed = transform.apply(set(piece))          # plaintext transformed coords (public obs)
        recovered = frozenset(transform.inverse().apply(observed))  # invert the public transform
        e4["trials"] += 1
        e4["exact_recoveries"] += int(recovered == piece)
    results["e4_transform_inversion"] = e4
    return results


def _bits(x: int) -> float:
    from math import log2

    return log2(x)
