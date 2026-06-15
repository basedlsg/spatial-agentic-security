"""Lab A solver: recover a hidden piece by searching the rigid-pose space.

The commitment is over the piece's absolute coordinates, so a single observation
O = g(P) restricts the search from the full secret space to the pose space
(24 rotations x (2b+1)^3 translations). The exhaustive solver enumerates that
finite space against the commitment oracle; the local solver is a cheaper window
heuristic whose miss rate is measured against the exhaustive one.
"""

from __future__ import annotations

from spatial_swarm.spatial_lab import commit as C
from spatial_swarm.spatial_lab.pose import (
    RigidPose,
    apply_pose,
    inverse_pose,
    pose_space_size,
    translation_grid,
)
from spatial_swarm.spatial_lab.solvers.base import Budget, SolverResult


def solve_exhaustive(
    *,
    observations,
    commitment: str,
    swarm_id: str,
    agent_id: str,
    repr_name: str,
    bound: int,
    budget: Budget,
) -> SolverResult:
    """Enumerate the full pose space of the first observation against the commitment."""

    budget.reset()
    if not observations:
        return SolverResult(False, 0, 0, 0.0, False, False, method="registration_exhaustive")
    o1 = observations[0]
    grid = translation_grid(bound)
    nodes = 0
    for rot in range(24):
        for t in grid:
            nodes += 1
            if budget.tripped(nodes):
                return SolverResult(
                    False, nodes, nodes, budget.elapsed(), True, False,
                    pose_space_size=pose_space_size(bound), method="registration_exhaustive",
                )
            candidate = apply_pose(inverse_pose(RigidPose(rot, t)), o1)
            if C.opens(commitment, swarm_id, agent_id, repr_name, candidate):
                return SolverResult(
                    True, nodes, nodes, budget.elapsed(), False, False,
                    recovered=candidate, pose_space_size=pose_space_size(bound),
                    method="registration_exhaustive",
                )
    return SolverResult(
        False, nodes, nodes, budget.elapsed(), False, True,
        pose_space_size=pose_space_size(bound), method="registration_exhaustive",
    )


def solve_local_window(
    *,
    observations,
    commitment: str,
    swarm_id: str,
    agent_id: str,
    repr_name: str,
    window: int,
    budget: Budget,
) -> SolverResult:
    """Heuristic: only search translations within a small window (24 x (2w+1)^3)."""

    budget.reset()
    if not observations:
        return SolverResult(False, 0, 0, 0.0, False, False, method="registration_local")
    o1 = observations[0]
    grid = translation_grid(window)
    nodes = 0
    for rot in range(24):
        for t in grid:
            nodes += 1
            if budget.tripped(nodes):
                return SolverResult(
                    False, nodes, nodes, budget.elapsed(), True, False,
                    pose_space_size=pose_space_size(window), method="registration_local",
                )
            candidate = apply_pose(inverse_pose(RigidPose(rot, t)), o1)
            if C.opens(commitment, swarm_id, agent_id, repr_name, candidate):
                return SolverResult(
                    True, nodes, nodes, budget.elapsed(), False, False,
                    recovered=candidate, pose_space_size=pose_space_size(window),
                    method="registration_local",
                )
    return SolverResult(
        False, nodes, nodes, budget.elapsed(), False, True,
        pose_space_size=pose_space_size(window), method="registration_local",
    )
