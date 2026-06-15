"""Pose/registration attacker -- reuses the spatial_lab exhaustive/local solvers.

Used by the generator's cheap-pose rejection gate and the leakage ladder's
transcript level.
"""

from __future__ import annotations

from spatial_swarm.spatial_lab.solvers.registration import solve_exhaustive, solve_local_window

__all__ = ["solve_exhaustive", "solve_local_window"]
