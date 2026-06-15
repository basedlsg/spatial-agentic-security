"""The observation ladder O0..O10 and the residual-enumerable subset.

The full ladder names every disclosure level. The leakage meter computes exact
residual candidate counts for the geometric, enumerable levels (shape, neighbors,
connector hint, topology hint, stolen sidecar); pose-only (O2), the fit oracle (O6,
a query model -> one-shot experiment), and timing (O9) are handled elsewhere or
noted, since they are not residual-enumerable here.
"""

from __future__ import annotations

from enum import IntEnum


class Obs(IntEnum):
    O0_COMMIT_ONLY = 0
    O1_OUTER_SHAPE = 1
    O2_OLD_TRANSCRIPT = 2
    O3_ONE_NEIGHBOR = 3
    O4_ALL_NEIGHBORS = 4
    O5_PARTIAL_PROJ = 5
    O6_FIT_ORACLE = 6
    O7_CONNECTOR_HINT = 7
    O8_TOPOLOGY_HINT = 8
    O9_TIMING_REASON = 9
    O10_STOLEN_SIDECAR = 10


def enumerable_levels(n_agents: int) -> list[tuple[str, dict]]:
    """(label, clue-flags) for the residual-enumerable levels, given n agents."""

    return [
        ("O1_outer_shape", dict(shape=True, revealed_count=0, connector=False, topology=False)),
        ("O7_connector_hint", dict(shape=True, revealed_count=0, connector=True, topology=False)),
        ("O8_topology_hint", dict(shape=True, revealed_count=0, connector=False, topology=True)),
        ("O7O8_both_hints", dict(shape=True, revealed_count=0, connector=True, topology=True)),
        ("O3_one_neighbor", dict(shape=True, revealed_count=1, connector=False, topology=False)),
        ("O10_stolen_sidecar", dict(shape=True, revealed_count=1, connector=True, topology=True)),
        ("O4_all_neighbors", dict(shape=True, revealed_count=max(0, n_agents - 1), connector=False, topology=False)),
    ]


# The O1 outer-shape level (shape only, no lossy clues) is the residual the random
# secret matches at equal entropy -> it is the ceiling every other cell is compared to.
RANDOM_CEILING_LABEL = "O1_outer_shape"
