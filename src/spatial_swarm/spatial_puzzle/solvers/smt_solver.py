"""Z3/SMT solver: exactly-k pseudo-boolean, enumerate models by blocking.

Demonstrates that even an SMT solver cannot shortcut the SHA-256 commitment: it
enumerates k-subsets and the commitment is checked in `consume`. UNSAT after
blocking => exhaustive.
"""

from __future__ import annotations

from spatial_swarm.spatial_lab.shapes import is_connected
from spatial_swarm.spatial_lab.solvers.base import Budget, SolverResult
from spatial_swarm.spatial_puzzle.solvers import optional
from spatial_swarm.spatial_puzzle.solvers.consume import CluePredicate, consume

NAME = "smt"


def solve(
    *,
    region,
    k: int,
    commitment: str,
    swarm_id: str,
    agent_id: str,
    repr_name: str,
    clue_predicate: CluePredicate = lambda _s: True,
    budget: Budget,
    mode: str = "count",
    require_connected: bool = True,
) -> SolverResult:
    if not optional.available(NAME):
        return SolverResult(False, 0, 0, 0.0, False, False, method=f"{NAME}:unavailable")
    z3 = optional.module(NAME)
    cells = sorted(region)
    b = {c: z3.Bool(f"b_{i}") for i, c in enumerate(cells)}
    solver = z3.Solver()
    solver.add(z3.PbEq([(b[c], 1) for c in cells], k))

    collected: list[frozenset] = []
    exhausted = True
    budget.reset()
    while True:
        if budget.tripped(len(collected)):
            exhausted = False
            break
        if solver.check() != z3.sat:
            break  # UNSAT -> all k-subsets enumerated
        model = solver.model()
        cand = frozenset(c for c in cells if z3.is_true(model.eval(b[c], model_completion=True)))
        collected.append(cand)
        solver.add(z3.Or([z3.Not(b[c]) for c in cand]))  # block exactly this k-subset

    pred = (lambda c: is_connected(c) and clue_predicate(c)) if require_connected else clue_predicate
    return consume(
        collected,
        commitment=commitment, swarm_id=swarm_id, agent_id=agent_id, repr_name=repr_name,
        clue_predicate=pred, budget=Budget(60.0, 50_000_000), mode=mode,
        method=NAME, exhaustive_source=exhausted,
    )
