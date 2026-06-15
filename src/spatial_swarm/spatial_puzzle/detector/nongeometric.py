"""NonGeometricTripwire: the baseline detector.

Sees only the commitment pass/fail per submission (via SwarmLifecycle) plus a probe
counter. Its response channel carries no information about *which* candidate the
secret is beyond pass/fail + liveness, so `reason_bits = 0`. This is the floor the
geometric detector is compared against.
"""

from __future__ import annotations

from spatial_swarm.spatial_puzzle.detector.base import (
    DetectionResult,
    Submission,
    build_lifecycles,
)
from spatial_swarm.spatial_puzzle.generators.visibility import HiddenSolution


class NonGeometricTripwire:
    name = "nongeometric_tripwire"

    def __init__(self, sol: HiddenSolution, *, one_shot: bool = True, strikes: int = 1) -> None:
        self._sol = sol
        self._one_shot = one_shot
        self._strikes = strikes
        self.probe_count = 0
        self.reset()

    def reset(self) -> None:
        self._lifecycles = build_lifecycles(self._sol, one_shot=self._one_shot, strikes=self._strikes)
        self.probe_count = 0

    def submit(self, sub: Submission) -> DetectionResult:
        self.probe_count += 1
        out = self._lifecycles[sub.agent_id].submit_proof(sub.candidate)
        return DetectionResult(
            released=out.released,
            blocked=out.blocked,
            flagged=out.blocked and not out.released,
            state=out.state.value,
            reason=out.reason,
            reason_bits=0.0,
            attribution=None,
        )
