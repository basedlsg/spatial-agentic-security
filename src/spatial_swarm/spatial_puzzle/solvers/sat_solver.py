"""PySAT solver: exactly-k cardinality CNF, enumerate models by blocking clauses.

Each model is a k-subset; connectivity + clue + commitment are filtered in
`consume`. UNSAT after blocking all found models => exhaustive.
"""

from __future__ import annotations

from spatial_swarm.spatial_lab.shapes import is_connected
from spatial_swarm.spatial_lab.solvers.base import Budget, SolverResult
from spatial_swarm.spatial_puzzle.solvers import optional
from spatial_swarm.spatial_puzzle.solvers.consume import CluePredicate, consume

NAME = "sat"


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
    from pysat.card import CardEnc, EncType
    from pysat.formula import IDPool
    from pysat.solvers import Solver

    cells = sorted(region)
    pool = IDPool()
    lit = {c: pool.id(("cell", c)) for c in cells}
    card = CardEnc.equals(lits=[lit[c] for c in cells], bound=k, vpool=pool, encoding=EncType.seqcounter)

    collected: list[frozenset] = []
    exhausted = True
    budget.reset()
    with Solver(name="glucose3", bootstrap_with=card.clauses) as sat:
        while True:
            if budget.tripped(len(collected)):
                exhausted = False
                break
            if not sat.solve():
                break  # UNSAT -> all k-subsets enumerated
            model = set(sat.get_model())
            cand = frozenset(c for c in cells if lit[c] in model)
            collected.append(cand)
            sat.add_clause([-lit[c] for c in cand])  # block exactly this k-subset

    pred = (lambda c: is_connected(c) and clue_predicate(c)) if require_connected else clue_predicate
    return consume(
        collected,
        commitment=commitment, swarm_id=swarm_id, agent_id=agent_id, repr_name=repr_name,
        clue_predicate=pred, budget=Budget(60.0, 50_000_000), mode=mode,
        method=NAME, exhaustive_source=exhausted,
    )
