"""Orchestrate the spatial-hardness sweep and aggregate the results.

For each tier and representation, run the attackers over many seeds, gate on the
positive controls, and aggregate success rates (with Clopper-Pearson intervals),
solver cost, the pose-space vs random-bruteforce comparison (Lab A), and the
candidate-count observation curve (Lab B). Entropy is matched across
representations by sizing R0/R1 to the same combinatorial space as the voxel
bounding cube.
"""

from __future__ import annotations

import math
import random
import statistics
from typing import Optional

from spatial_swarm.experiments.metrics import _latency_summary
from spatial_swarm.experiments.stats import clopper_pearson
from spatial_swarm.spatial_lab import attackers as AT
from spatial_swarm.spatial_lab import controls
from spatial_swarm.spatial_lab.entropy import bands_overlap
from spatial_swarm.spatial_lab.observe import observe
from spatial_swarm.spatial_lab.pose import pose_space_size
from spatial_swarm.spatial_lab.representations import (
    REPRESENTATIONS,
    build_swarm,
    commitment_only_entropy,
)
from spatial_swarm.spatial_lab.solvers.base import Budget

# Tier settings: small EXACT (enumerable) and larger SCALING (budgeted).
TIERS = {
    "exact": {"n": 3, "k": 4, "bound": 2, "exact": True, "budget": (3.0, 1_000_000)},
    "scaling": {"n": 4, "k": 8, "bound": 2, "exact": False, "budget": (8.0, 3_000_000)},
}


def _tier_params(n: int, k: int) -> tuple[dict, int]:
    side = 1
    while side**3 < n * k:
        side += 1
    vol = side**3
    params = {
        "R0": {"m": vol},
        "R1": {"p": side},
        "R2": {"mode": "grown"},
        "R3": {"mode": "grown"},
        "R4": {"mode": "grown"},
    }
    return params, vol


def _middle(sw) -> str:
    ids = sw.agent_ids()
    return ids[len(ids) // 2]


def _agg(outcomes) -> dict:
    n = len(outcomes)
    found = sum(1 for o in outcomes if o.found)
    low, high = clopper_pearson(found, n) if n else (0.0, 1.0)
    return {
        "trials": n,
        "found": found,
        "found_rate": found / n if n else 0.0,
        "found_rate_ci95": {"low": low, "high": high},
        "budget_hits": sum(1 for o in outcomes if o.budget_hit),
        "wall_seconds": _latency_summary([o.wall_seconds for o in outcomes]),
        "nodes": _latency_summary([float(o.nodes) for o in outcomes]),
        "median_iou_when_found": _median_iou(outcomes),
    }


def _median_iou(outcomes) -> Optional[float]:
    ious = [o.reconstruction["iou"] for o in outcomes if o.found and o.reconstruction]
    return statistics.median(ious) if ious else None


def run_experiment(
    *,
    tiers: tuple[str, ...] = ("exact",),
    reprs: tuple[str, ...] = REPRESENTATIONS,
    labs: tuple[str, ...] = ("A", "B"),
    seeds: int = 20,
    llm_provider: Optional[AT.LLMProvider] = None,
    seed_base: int = 1000,
) -> dict:
    seed_list = list(range(seed_base, seed_base + seeds))
    out: dict = {
        "config": {
            "tiers": list(tiers),
            "reprs": list(reprs),
            "labs": list(labs),
            "seeds": seeds,
            "tier_settings": {t: TIERS[t] for t in tiers},
        },
        "entropy_matching": {},
        "positive_controls": {"valid": True},
        "lab_A_registration": {},
        "lab_B_assembly": {},
        "observation_curves": {},
        "pose_space_vs_random_bruteforce": {},
        "llm_attacker": {"status": "not_run" if llm_provider is None else "configured"},
    }

    for tier in tiers:
        cfg = TIERS[tier]
        n, k, bound, is_exact = cfg["n"], cfg["k"], cfg["bound"], cfg["exact"]
        params, _vol = _tier_params(n, k)

        def budget() -> Budget:
            return Budget(*cfg["budget"])

        accts = {r: commitment_only_entropy(r, n, k, params[r]) for r in reprs}
        out["entropy_matching"][tier] = {
            "per_repr": {
                r: {"bits": accts[r].secret_space_bits, "basis": accts[r].basis,
                    "upper_bound": accts[r].is_upper_bound}
                for r in reprs
            },
            "matched": bands_overlap(list(accts.values()), tolerance_bits=1.0),
        }

        # ---- positive controls (gate) ----
        ctrl: dict = {}
        for r in reprs:
            entry: dict = {}
            if "A" in labs and r in controls.LAB_A_REPRS:
                entry["planted_pose"] = (
                    "pass" if controls.check_planted_pose(r, random.Random(7), n, k, params[r], "ctrl", bound, budget()) else "fail"
                )
            if "B" in labs and r in controls.LAB_B_REPRS:
                entry["planted_piece"] = (
                    "pass" if controls.check_planted_piece(r, random.Random(7), n, k, params[r], "ctrl", budget()) else "fail"
                )
            if entry:
                ctrl[r] = entry
        out["positive_controls"][tier] = ctrl
        if any(v == "fail" for e in ctrl.values() for v in e.values()):
            out["positive_controls"]["valid"] = False

        # ---- Lab A: unknown-pose registration ----
        if "A" in labs:
            lab_a: dict = {}
            pose_vs: dict = {}
            pose_bits = math.log2(pose_space_size(bound))
            for r in reprs:
                if r not in controls.LAB_A_REPRS:
                    continue
                reg, loc, rnd, nbr = [], [], [], []
                for s in seed_list:
                    sw = build_swarm(r, random.Random(s), n, k, params[r], f"{tier}-A-{r}-{s}")
                    agent = _middle(sw)
                    obs = observe(sw.pieces[agent], random.Random(s + 99991), count=1, bound=bound)
                    reg.append(AT.lab_a_registration(sw, agent, obs, bound, budget()))
                    loc.append(AT.lab_a_local(sw, agent, obs, window=1, budget=budget()))
                    rnd.append(AT.lab_a_random_pose(sw, agent, obs, bound, Budget(0.3, 20_000), seed=s))
                    nbr.append(AT.lab_a_neighbor_copy(sw, agent, bound, budget()))
                lab_a[r] = {
                    "registration_exhaustive": _agg(reg),
                    "registration_local_window1": _agg(loc),
                    "random_pose": _agg(rnd),
                    "neighbor_copy": _agg(nbr),
                }
                pose_vs[r] = {
                    "pose_space_bits": pose_bits,
                    "random_commitment_bits": accts[r].secret_space_bits,
                    "observation_saves_bits": accts[r].secret_space_bits - pose_bits,
                }
            out["lab_A_registration"][tier] = lab_a
            out["pose_space_vs_random_bruteforce"][tier] = pose_vs

        # ---- Lab B: assembly constraint-search ----
        if "B" in labs:
            lab_b: dict = {}
            curves: dict = {}
            for r in reprs:
                if r == "R0":
                    lab_b[r] = {
                        "note": "no shared object; published constraints uninformative; full secret space",
                        "secret_space_bits": accts["R0"].secret_space_bits,
                        "found_rate": 0.0,
                    }
                    continue
                if r not in controls.LAB_B_REPRS:
                    continue
                asm, nbr = [], []
                per_reveal: dict[int, list[int]] = {rev: [] for rev in range(n)}
                for s in seed_list:
                    sw = build_swarm(r, random.Random(s), n, k, params[r], f"{tier}-B-{r}-{s}")
                    agent = _middle(sw)
                    asm.append(AT.lab_b_assembly(sw, agent, 0, budget(), exact=is_exact))
                    nbr.append(AT.lab_b_neighbor_copy(sw, agent))
                    for rev in range(n):
                        o = AT.lab_b_assembly(sw, agent, rev, budget(), exact=is_exact)
                        if o.consistent_candidates is not None:
                            per_reveal[rev].append(o.consistent_candidates)
                lab_b[r] = {"assembly_backtrack": _agg(asm), "neighbor_copy": _agg(nbr)}
                curves[r] = [
                    {
                        "revealed_others": rev,
                        "median_consistent_candidates": (
                            statistics.median(per_reveal[rev]) if per_reveal[rev] else None
                        ),
                        "exhausted_fraction": len(per_reveal[rev]) / len(seed_list),
                    }
                    for rev in range(n)
                ]
            out["lab_B_assembly"][tier] = lab_b
            out["observation_curves"][tier] = curves

        # ---- LLM hook (one instance per voxel repr if a provider is configured) ----
        if llm_provider is not None:
            llm_runs = {}
            for r in reprs:
                if r == "R0":
                    continue
                sw = build_swarm(r, random.Random(seed_base), n, k, params[r], f"{tier}-llm-{r}")
                agent = _middle(sw)
                outcome = AT.llm_attacker(sw, agent, None, provider=llm_provider)
                llm_runs[r] = outcome.public_dict()
            out["llm_attacker"].setdefault("runs", {})[tier] = llm_runs

    return out
