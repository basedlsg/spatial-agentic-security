"""Small text visualization helpers for early demos."""

from __future__ import annotations

from collections.abc import Mapping

from spatial_swarm.geometry.finite_grid import Coord


def summarize_point_cloud(point_sets: Mapping[str, set[Coord]]) -> str:
    """Return a compact non-sensitive summary of transformed fragments."""

    lines = []
    for agent_id, coords in sorted(point_sets.items()):
        xs = [coord[0] for coord in coords]
        ys = [coord[1] for coord in coords]
        zs = [coord[2] for coord in coords]
        lines.append(
            f"{agent_id}: n={len(coords)} "
            f"x=[{min(xs)},{max(xs)}] y=[{min(ys)},{max(ys)}] z=[{min(zs)},{max(zs)}]"
        )
    return "\n".join(lines)
