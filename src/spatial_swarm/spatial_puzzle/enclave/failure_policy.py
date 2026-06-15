"""One-shot failure policy: a wrong proof destroys the swarm (no retry).

Software policy, testable locally. A correct proof releases; a wrong proof under
one-shot marks the swarm dead, wipes sidecars, and zeroizes state, so no further
probing is possible.

`strikes` (default 1) is the number of wrong proofs tolerated before shutdown when
`one_shot` is True; `strikes=1` is exactly the original one-shot behavior. It exists
so the repeated-probing axis can be measured (with `strikes>1`) instead of being
degenerate (every detector dies on the first wrong proof). `one_shot=False` keeps the
unlimited-retry mode and ignores `strikes`.
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
    strikes: int = 1                     # wrong proofs tolerated before shutdown (one_shot only)
    state: SwarmState = SwarmState.ALIVE
    sidecars: dict = field(default_factory=dict)
    zeroized: bool = False
    wrong_count: int = 0                 # wrong proofs seen so far

    def submit_proof(self, candidate) -> PolicyOutcome:
        if self.state is SwarmState.DEAD:
            return PolicyOutcome(False, True, SwarmState.DEAD, True, self.zeroized, False, "swarm_dead")
        if self.opens(frozenset(candidate)):
            return PolicyOutcome(True, False, self.state, False, False, True, "released")
        # wrong proof
        self.wrong_count += 1
        if self.one_shot and self.wrong_count >= self.strikes:
            self.state = SwarmState.DEAD
            self.sidecars.clear()
            self.zeroized = True
            return PolicyOutcome(False, True, SwarmState.DEAD, True, True, False, "wrong_proof_destroyed")
        return PolicyOutcome(False, True, SwarmState.ALIVE, False, False, True, "wrong_proof_retry")
