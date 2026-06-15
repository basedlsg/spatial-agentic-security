"""One-shot failure policy: a wrong proof destroys the swarm (no retry).

Software policy, testable locally. A correct proof releases; a wrong proof under
one-shot marks the swarm dead, wipes sidecars, and zeroizes state, so no further
probing is possible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Callable


class SwarmState(str, Enum):
    ALIVE = "alive"
    DEAD = "dead"


@dataclass(frozen=True)
class PolicyOutcome:
    released: bool
    blocked: bool
    state: SwarmState
    sidecars_wiped: bool
    zeroized: bool
    retry_allowed: bool
    reason: str


@dataclass
class SwarmLifecycle:
    swarm_id: str
    opens: Callable[[frozenset], bool]   # commitment-opening check for the target agent
    one_shot: bool = True
    state: SwarmState = SwarmState.ALIVE
    sidecars: dict = field(default_factory=dict)
    zeroized: bool = False

    def submit_proof(self, candidate) -> PolicyOutcome:
        if self.state is SwarmState.DEAD:
            return PolicyOutcome(False, True, SwarmState.DEAD, True, self.zeroized, False, "swarm_dead")
        if self.opens(frozenset(candidate)):
            return PolicyOutcome(True, False, self.state, False, False, True, "released")
        # wrong proof
        if self.one_shot:
            self.state = SwarmState.DEAD
            self.sidecars.clear()
            self.zeroized = True
            return PolicyOutcome(False, True, SwarmState.DEAD, True, True, False, "wrong_proof_destroyed")
        return PolicyOutcome(False, True, SwarmState.ALIVE, False, False, True, "wrong_proof_retry")
