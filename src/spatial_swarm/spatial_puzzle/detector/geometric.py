"""GeometricDetector: the commitment tripwire plus runtime 3D checks (and optional decoy).

The release/catch decision is IDENTICAL to the baseline (same SwarmLifecycle): geometry
is layered on, never replaces the commitment. Two `reason_mode`s isolate the leak cost:

- ``silent``  : runs the geometric checks but returns the same opaque reason as the
  baseline, so `reason_bits = 0`. Shows runtime geometry adds nothing when it does
  not leak.
- ``verbose`` : returns which geometric check failed (a fit/no-fit oracle), so
  `reason_bits > 0`. The cost is measured, not assumed.

Optional ``decoy_hist`` (a connector histogram no legitimate piece produces) is the
honeypot: a submission consistent with the decoy is flagged with
``attribution="decoy_consistent"`` but the release decision is unchanged.
"""

from __future__ import annotations

import math
from typing import Optional

from spatial_swarm.spatial_lab.shapes import is_connected
from spatial_swarm.spatial_puzzle.detector.base import (
    DetectionResult,
    Submission,
    build_lifecycles,
)
from spatial_swarm.spatial_puzzle.generators.build import derive_public_view
from spatial_swarm.spatial_puzzle.generators.polycube import connector_histogram, topology_band
from spatial_swarm.spatial_puzzle.generators.visibility import (
    HiddenSolution,
    PublicView,
    region_for,
)

# Distinct wrong-reasons the verbose mode can emit (vocabulary-size upper bound on leak).
_VERBOSE_REASONS = ("wrong_shape_membership", "wrong_connector_histogram",
                    "wrong_topology_band", "wrong_proof_destroyed")


class GeometricDetector:
    name = "geometric_detector"

    def __init__(
        self,
        sol: HiddenSolution,
        *,
        one_shot: bool = True,
        strikes: int = 1,
        reason_mode: str = "silent",      # "silent" | "verbose"
        revealed_count: int = 0,
        decoy_hist: Optional[tuple] = None,
    ) -> None:
        if reason_mode not in ("silent", "verbose"):
            raise ValueError(f"unknown reason_mode: {reason_mode}")
        self._sol = sol
        self._one_shot = one_shot
        self._strikes = strikes
        self._reason_mode = reason_mode
        self._revealed_count = revealed_count
        self._decoy_hist = decoy_hist
        self._views: dict[str, PublicView] = {
            aid: derive_public_view(
                sol, aid, shape=True, revealed_count=revealed_count, connector=True, topology=True
            )
            for aid in sol.agent_ids()
        }
        self.probe_count = 0
        self.reset()

    def reset(self) -> None:
        self._lifecycles = build_lifecycles(self._sol, one_shot=self._one_shot, strikes=self._strikes)
        self.probe_count = 0

    def name_with_mode(self) -> str:
        return f"{self.name}:{self._reason_mode}" + (":decoy" if self._decoy_hist is not None else "")

    def _reason_bits(self) -> float:
        if self._reason_mode == "verbose":
            return math.log2(len(_VERBOSE_REASONS))
        return 0.0

    def _decoy_consistent(self, cand: frozenset, view: PublicView) -> bool:
        if self._decoy_hist is None or view.outer_shape is None:
            return False
        return connector_histogram(cand, view.outer_shape, view.alphabet_size) == self._decoy_hist

    def _geometry_reason(self, cand: frozenset, view: PublicView) -> str:
        region = region_for(view)
        if len(cand) != view.k or not (cand <= region) or not is_connected(cand):
            return "wrong_shape_membership"
        if view.connector_hist is not None and view.outer_shape is not None:
            if connector_histogram(cand, view.outer_shape, view.alphabet_size) != view.connector_hist:
                return "wrong_connector_histogram"
        if view.topology_band_value is not None:
            if topology_band(cand, view.topo_bucket) != view.topology_band_value:
                return "wrong_topology_band"
        return "wrong_proof_destroyed"

    def submit(self, sub: Submission) -> DetectionResult:
        self.probe_count += 1
        view = self._views[sub.agent_id]
        out = self._lifecycles[sub.agent_id].submit_proof(sub.candidate)

        flagged = out.blocked and not out.released
        attribution: Optional[str] = None
        if self._decoy_consistent(sub.candidate, view):
            flagged = True
            attribution = "decoy_consistent"

        if out.released:
            reason = out.reason
        elif self._reason_mode == "verbose":
            reason = self._geometry_reason(sub.candidate, view)
        else:
            reason = out.reason  # silent: opaque, identical to baseline

        return DetectionResult(
            released=out.released,
            blocked=out.blocked,
            flagged=flagged,
            state=out.state.value,
            reason=reason,
            reason_bits=self._reason_bits(),
            attribution=attribution,
        )
