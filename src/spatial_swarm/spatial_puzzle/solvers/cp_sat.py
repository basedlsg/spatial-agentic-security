"""OR-Tools CP-SAT solver: enumerate k-subsets via constraint search, filter+commit.

Native constraint: exactly-k cells selected. All solutions are enumerated; the
SHA-256 commitment (and connectivity/clue predicate) are filtered in `consume`,
because the commitment is a hash CP-SAT cannot reason about -- so CP-SAT prunes the
geometry set and the residual after that is exactly what the attacker faces.
"""

from __future__ import annotations

from spatial_swarm.spatial_lab.shapes import is_connected
from spatial_swarm.spatial_lab.solvers.base import Budget, SolverResult
from spatial_swarm.spatial_puzzle.solvers import optional
from spatial_swarm.spatial_puzzle.solvers.consume import CluePredicate, consume

NAME = "cp_sat"


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
    solution_cap: int = 500_000,
) -> SolverResult:
    if not optional.available(NAME):
        return SolverResult(False, 0, 0, 0.0, False, False, method=f"{NAME}:unavailable")
    cp = optional.module(NAME)
    cells = sorted(region)
    model = cp.CpModel()
    x = {c: model.NewBoolVar(f"x_{i}") for i, c in enumerate(cells)}
    model.Add(sum(x.values()) == k)

    collected: list[frozenset] = []
    state = {"capped": False}

    class _CB(cp.CpSolverSolutionCallback):
        def __init__(self) -> None:
            cp.CpSolverSolutionCallback.__init__(self)
            self.count = 0

        def on_solution_callback(self) -> None:
            collected.append(frozenset(c for c in cells if self.Value(x[c])))
            self.count += 1
            if self.count >= solution_cap:
                state["capped"] = True
                self.StopSearch()

    solver = cp.CpSolver()
    solver.parameters.enumerate_all_solutions = True
    solver.parameters.max_time_in_seconds = budget.max_seconds
    status = solver.Solve(model, _CB())
    exhaustive = (status == cp.OPTIMAL) and not state["capped"]

    pred = (lambda c: is_connected(c) and clue_predicate(c)) if require_connected else clue_predicate
    return consume(
        collected,
        commitment=commitment, swarm_id=swarm_id, agent_id=agent_id, repr_name=repr_name,
        clue_predicate=pred, budget=Budget(60.0, 50_000_000), mode=mode,
        method=NAME, exhaustive_source=exhaustive,
    )
