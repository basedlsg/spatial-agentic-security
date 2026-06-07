"""Assembly checks for transformed fragments."""

from __future__ import annotations

from collections.abc import Mapping

from spatial_swarm.geometry.finite_grid import Coord
from spatial_swarm.geometry.fragment import Fragment
from spatial_swarm.geometry.transform import AffineTransform


def transformed_target(fragments: Mapping[str, Fragment], transform: AffineTransform) -> set[Coord]:
    target: set[Coord] = set()
    for fragment in fragments.values():
        transformed = transform.apply(fragment.coords)
        if target.intersection(transformed):
            raise ValueError("transformed fragments are not disjoint")
        target.update(transformed)
    return target


def assembles_exactly(
    submitted: Mapping[str, set[Coord]],
    fragments: Mapping[str, Fragment],
    transform: AffineTransform,
) -> bool:
    if set(submitted) != set(fragments):
        return False

    assembled: set[Coord] = set()
    for agent_id, coords in submitted.items():
        expected = transform.apply(fragments[agent_id].coords)
        if coords != expected:
            return False
        if assembled.intersection(coords):
            return False
        assembled.update(coords)

    return assembled == transformed_target(fragments, transform)
