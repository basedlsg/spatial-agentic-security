"""Metrics, confidence intervals, the 8 gating positive controls, and redaction for PCS.

Every rate carries a Clopper-Pearson 95% interval. A run is INVALID (no findings) if any
positive control fails. The redaction marker set extends the baseline with spatial-secret
markers; a planted-secret control proves the scanner works.
"""

from __future__ import annotations

import math
import random
from pathlib import Path

from spatial_swarm.experiments.redaction import SECRET_MARKERS, scan_run_dir
from spatial_swarm.experiments.stats import clopper_pearson
from spatial_swarm.spatial_lab import commit as C
from spatial_swarm.spatial_lab.solvers.base import Budget
from spatial_swarm.spatial_puzzle.detector.base import Submission
from spatial_swarm.spatial_puzzle.detector.geometric import GeometricDetector
from spatial_swarm.spatial_puzzle.enclave.failure_policy import SwarmLifecycle, SwarmState
from spatial_swarm.spatial_puzzle.generators.build import build_hidden_solution, derive_public_view
from spatial_swarm.spatial_puzzle.generators.visibility import clue_predicate_for, region_for
from spatial_swarm.spatial_puzzle.solvers import pure_enum

# Baseline markers + spatial-secret markers (redaction.py left unchanged; custom markers passed in).
PCS_MARKERS = tuple(SECRET_MARKERS) + ("connector_label", "topology_secret", "raw_piece", "sidecar_secret")


def proportion(successes: int, n: int) -> dict:
    low, high = clopper_pearson(successes, n) if n else (0.0, 1.0)
    return {"successes": successes, "n": n, "rate": (successes / n if n else 0.0),
            "ci95": {"low": low, "high": high}}


def one_shot_success(residual: int | None) -> float | None:
    return (1.0 / residual) if residual else None


def entropy_lost_bits(ceiling: int | None, residual: int | None) -> float | None:
    if not ceiling or not residual:
        return None
    return math.log2(ceiling) - math.log2(residual)


def scan_for_secrets(run_dir: Path) -> dict:
    """Redaction report over a run dir using the extended marker set."""

    hits = scan_run_dir(run_dir, markers=PCS_MARKERS)
    return {
        "markers_checked": list(PCS_MARKERS),
        "secret_markers_found": len(hits),
        "hits": [{"path": h.path, "marker": h.marker} for h in hits],
        "clean": not hits,
    }


def planted_secret_control(tmp_dir: Path) -> dict:
    """Write a file with planted secret markers OUTSIDE the run dir; confirm scan_run_dir finds them.

    Proves the file scanner works. The caller must pass a directory that is NOT inside the
    scanned run directory, so the planted secret never pollutes the real redaction scan.
    """

    tmp_dir.mkdir(parents=True, exist_ok=True)
    planted = '{"coords": [[1,2,3]], "signing_key": "deadbeef", "connector_label": 2, "raw_piece": [[0,0,0]]}'
    (tmp_dir / "planted_secret_control.txt").write_text(planted, encoding="utf-8")
    hits = scan_run_dir(tmp_dir, markers=PCS_MARKERS)
    # report only a count + boolean -- never the literal marker strings, which would
    # otherwise re-trigger the scanner when this result is serialized into metrics.json.
    return {"planted_markers_found_count": len({h.marker for h in hits}), "detected": len(hits) >= 3}


def positive_controls(*, n: int, k: int, tmp_dir: Path, seed: int = 9999,
                      budget: tuple[float, int] = (10.0, 3_000_000)) -> dict:
    """The 8 required controls. `valid` is True only if all pass; else the run is invalid."""

    sol = build_hidden_solution(random.Random(seed), n=n, k=k, swarm_id=f"ctrl-{seed}")
    agent = sol.agent_ids()[len(sol.agent_ids()) // 2]
    true_piece = sol.pieces[agent]
    # a far-away connected k-line that cannot open any commitment in this swarm
    wrong = frozenset((99, 99, 99 - i) for i in range(k))

    def opener(cand):
        return C.opens(sol.commitments[agent], sol.swarm_id, agent, sol.repr_name, cand)

    # 1 true piece releases
    c1 = SwarmLifecycle(sol.swarm_id, opener, one_shot=True).submit_proof(true_piece).released
    # 2 wrong random piece blocks
    c2_out = SwarmLifecycle(sol.swarm_id, opener, one_shot=True).submit_proof(wrong)
    c2 = c2_out.blocked and not c2_out.released
    # 3 commitment-opening candidate releases (the true piece opens the commitment)
    c3 = opener(true_piece) is True
    # 4 verbose detector leaks (reason_bits > 0 on a wrong submission)
    rv = GeometricDetector(sol, reason_mode="verbose").submit(Submission(sol.swarm_id, agent, wrong, "x"))
    c4 = rv.reason_bits > 0.0
    # 5 silent detector leaks zero reason bits
    rs = GeometricDetector(sol, reason_mode="silent").submit(Submission(sol.swarm_id, agent, wrong, "x"))
    c5 = rs.reason_bits == 0.0
    # 6 solver solves a planted easy case (all neighbors revealed -> region == true piece)
    view = derive_public_view(sol, agent, shape=True, revealed_count=max(0, len(sol.agent_ids()) - 1),
                              connector=False, topology=False)
    res = pure_enum.solve(region=region_for(view), k=k, commitment=sol.commitments[agent],
                          swarm_id=sol.swarm_id, agent_id=agent, repr_name=sol.repr_name,
                          clue_predicate=clue_predicate_for(view), budget=Budget(*budget),
                          mode="recover", require_connected=True)
    c6 = res.found and res.recovered == true_piece
    # 7 redaction scanner finds a planted secret
    c7 = planted_secret_control(tmp_dir / "controls")["detected"]
    # 8 destroy blocks a second attempt (one-shot)
    lc = SwarmLifecycle(sol.swarm_id, opener, one_shot=True, strikes=1)
    lc.submit_proof(wrong)
    second = lc.submit_proof(true_piece)
    c8 = lc.state is SwarmState.DEAD and second.blocked and not second.released

    controls = {
        "control_true_piece_releases": bool(c1),
        "control_wrong_random_piece_blocks": bool(c2),
        "control_commitment_opening_releases": bool(c3),
        "control_verbose_leak_detected": bool(c4),
        "control_silent_reason_leaks_zero": bool(c5),
        "control_solver_solves_planted_easy_case": bool(c6),
        "control_redaction_scanner_finds_planted_secret": bool(c7),
        "control_destroy_blocks_second_attempt": bool(c8),
    }
    controls["valid"] = all(controls.values())
    return controls
