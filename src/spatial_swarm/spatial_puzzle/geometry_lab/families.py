"""Formation family generators for the geometry lab."""

from __future__ import annotations

import math
import statistics
from dataclasses import dataclass

from spatial_swarm.crypto.hashing import sha256_hex
from spatial_swarm.spatial_puzzle.geometry_lab.formation_spec import (
    AgentTrajectory,
    FormationSpec,
    Point,
    agent_ids,
    role_for_index,
)

FEATURES = (
    "endpoint",
    "path",
    "timing",
    "collision",
    "forbidden_region",
    "path_crossing",
    "final_shape",
    "role_binding",
    "topology",
)


@dataclass(frozen=True)
class FamilyProfile:
    name: str
    features: frozenset[str]
    generation_base: float
    generation_per_agent: float
    runtime_weight: float
    leakage_one: float
    leakage_two: float
    symmetry_base: int
    notes: str


FAMILY_PROFILES: dict[str, FamilyProfile] = {
    "lattice": FamilyProfile(
        "lattice",
        frozenset({"endpoint", "path", "timing", "collision", "final_shape", "role_binding"}),
        0.0,
        0.0,
        0.7,
        0.35,
        0.75,
        2,
        "fast separated lattice baseline",
    ),
    "sphere_shell": FamilyProfile(
        "sphere_shell",
        frozenset({"endpoint", "path", "timing", "collision", "final_shape", "role_binding"}),
        0.001,
        0.00003,
        1.2,
        1.05,
        2.15,
        18,
        "global shell shape with symmetry risk",
    ),
    "helix": FamilyProfile(
        "helix",
        frozenset(
            {
                "endpoint",
                "path",
                "timing",
                "collision",
                "path_crossing",
                "final_shape",
                "role_binding",
                "topology",
            }
        ),
        0.002,
        0.00004,
        1.8,
        0.55,
        1.10,
        5,
        "phase and turn-count sensitive curved paths",
    ),
    "polytope": FamilyProfile(
        "polytope",
        frozenset({"endpoint", "path", "timing", "collision", "final_shape", "role_binding"}),
        0.003,
        0.00004,
        1.1,
        0.85,
        1.75,
        12,
        "rigid final skeleton with symmetry risk",
    ),
    "obstacle_field": FamilyProfile(
        "obstacle_field",
        frozenset(
            {
                "endpoint",
                "path",
                "timing",
                "collision",
                "forbidden_region",
                "path_crossing",
                "final_shape",
                "role_binding",
            }
        ),
        0.010,
        0.00018,
        2.2,
        0.45,
        0.90,
        3,
        "private forbidden regions and detour paths",
    ),
    "braid": FamilyProfile(
        "braid",
        frozenset(
            {
                "endpoint",
                "path",
                "timing",
                "collision",
                "forbidden_region",
                "path_crossing",
                "final_shape",
                "role_binding",
                "topology",
            }
        ),
        0.018,
        0.00042,
        3.6,
        0.25,
        0.55,
        4,
        "crossing order and path-history formation",
    ),
    "voronoi": FamilyProfile(
        "voronoi",
        frozenset(
            {
                "endpoint",
                "path",
                "timing",
                "collision",
                "forbidden_region",
                "final_shape",
                "role_binding",
            }
        ),
        0.012,
        0.00030,
        2.0,
        2.45,
        5.25,
        7,
        "private cells with explicit neighbor-leak risk",
    ),
}

FAMILY_NAMES = tuple(FAMILY_PROFILES)


def profile_for(family_name: str) -> FamilyProfile:
    try:
        return FAMILY_PROFILES[family_name]
    except KeyError as exc:
        raise ValueError(f"unknown geometry family: {family_name}") from exc


def generation_failure_rate(family_name: str, agent_count: int) -> float:
    profile = profile_for(family_name)
    return min(0.30, profile.generation_base + profile.generation_per_agent * agent_count)


def generation_failed(family_name: str, agent_count: int, trial_index: int) -> bool:
    threshold = int(generation_failure_rate(family_name, agent_count) * 100_000)
    if threshold <= 0:
        return False
    value = _stable_int("generation_failure", family_name, agent_count, trial_index) % 100_000
    return value < threshold


def generate_family_spec(
    family_name: str,
    agent_count: int,
    trial_index: int,
    *,
    grid_size: int = 64,
    time_steps: int = 24,
    action_hash: str | None = None,
    nonce: str | None = None,
    risk_level: str = "high",
) -> FormationSpec:
    profile = profile_for(family_name)
    agents = agent_ids(agent_count)
    action_hash = action_hash or sha256_hex(
        {"kind": "geometry_lab_action", "family": family_name, "agents": agent_count, "trial": trial_index}
    )
    nonce = nonce or sha256_hex(
        {"kind": "geometry_lab_nonce", "family": family_name, "agents": agent_count, "trial": trial_index}
    )[:32]
    endpoints = _endpoints(family_name, agents, trial_index, grid_size)
    obstacles = _obstacles(family_name, trial_index, grid_size)
    trajectories = []
    for index, agent in enumerate(agents):
        endpoint = endpoints[agent]
        path = _path(family_name, index, len(agents), endpoint, trial_index, grid_size, time_steps, obstacles)
        role = role_for_index(index)
        trajectories.append(
            AgentTrajectory(
                agent_id=agent,
                role=role,
                start_point=path[0],
                endpoint=endpoint,
                path=path,
                timing_window=(index % 3, time_steps - 1 + (index % 3)),
                private_digest=sha256_hex(
                    {
                        "kind": "geometry_agent_private_digest",
                        "family": family_name,
                        "trial": trial_index,
                        "agent": agent,
                        "endpoint": list(endpoint),
                    }
                ),
            )
        )
    endpoint_items = tuple(sorted((agent, point) for agent, point in endpoints.items()))
    path_items = tuple(sorted((trajectory.agent_id, trajectory.path) for trajectory in trajectories))
    role_items = tuple(sorted((trajectory.agent_id, trajectory.role) for trajectory in trajectories))
    timing_items = tuple((trajectory.agent_id, trajectory.timing_window) for trajectory in trajectories)
    crossing_rules = _crossing_rules(family_name, trajectories)
    feature_signatures = {
        "endpoint": _digest_points("endpoint", endpoint_items),
        "path": sha256_hex(
            {
                "kind": "geometry_feature_path",
                "paths": [
                    (agent, [list(point) for point in path])
                    for agent, path in path_items
                ],
            }
        ),
        "timing": sha256_hex({"kind": "geometry_feature_timing", "timing": list(timing_items)}),
        "collision": sha256_hex(
            {
                "kind": "geometry_feature_collision",
                "family": family_name,
                "agent_count": len(agents),
                "time_steps": time_steps,
                "collision_rule": "no_same_time_same_voxel",
            }
        ),
        "forbidden_region": sha256_hex(
            {
                "kind": "geometry_feature_forbidden",
                "obstacle_map": [list(point) for point in obstacles],
                "margin": forbidden_region_margin(tuple(t.path for t in trajectories), obstacles),
            }
        ),
        "path_crossing": sha256_hex(
            {"kind": "geometry_feature_crossing", "crossing_rules": list(crossing_rules)}
        ),
        "final_shape": sha256_hex(
            {
                "kind": "geometry_feature_final_shape",
                "family": family_name,
                "points": [list(point) for _, point in endpoint_items],
            }
        ),
        "role_binding": sha256_hex(
            {
                "kind": "geometry_feature_role_binding",
                "roles": list(role_items),
                "endpoints": [(agent, list(point)) for agent, point in endpoint_items],
            }
        ),
        "topology": sha256_hex(
            {
                "kind": "geometry_feature_topology",
                "family": family_name,
                "crossing": list(crossing_rules),
                "obstacle_count": len(obstacles),
                "features": sorted(profile.features),
            }
        ),
    }
    return FormationSpec(
        family_name=family_name,
        agent_ids=agents,
        action_hash=action_hash,
        nonce=nonce,
        risk_level=risk_level,
        grid_size=grid_size,
        time_steps=time_steps,
        endpoints=endpoint_items,
        paths=path_items,
        role_map=role_items,
        obstacle_map=tuple(sorted(obstacles)),
        collision_rules=(("min_distance", ">=1"),),
        crossing_rules=crossing_rules,
        final_shape_signature=feature_signatures["final_shape"],
        topology_signature=feature_signatures["topology"],
        trajectories=tuple(trajectories),
        feature_signatures=tuple(sorted(feature_signatures.items())),
    )


def estimated_runtime_ms(family_name: str, agent_count: int, time_steps: int) -> float:
    profile = profile_for(family_name)
    base = profile.runtime_weight * agent_count * max(1, math.log2(time_steps + 1)) / 9.0
    topology_cost = 0.0
    if "topology" in profile.features:
        topology_cost = profile.runtime_weight * math.log2(agent_count + 1) / 4.0
    return round(base + topology_cost, 4)


def path_length_stats(spec: FormationSpec) -> dict[str, float]:
    lengths = [_path_length(path) for _, path in spec.paths]
    if not lengths:
        return {"mean": 0.0, "variance": 0.0}
    return {
        "mean": float(statistics.mean(lengths)),
        "variance": float(statistics.pvariance(lengths)),
    }


def minimum_agent_distance(paths: tuple[tuple[Point, ...], ...]) -> float:
    best = math.inf
    if len(paths) < 2:
        return math.inf
    steps = min(len(path) for path in paths)
    for t in range(steps):
        for i in range(len(paths)):
            for j in range(i + 1, len(paths)):
                best = min(best, _distance(paths[i][t], paths[j][t]))
    return 0.0 if math.isinf(best) else float(best)


def endpoint_margin(spec: FormationSpec) -> float:
    points = [point for _, point in spec.endpoints]
    if len(points) < 2:
        return math.inf
    return min(_distance(a, b) for i, a in enumerate(points) for b in points[i + 1 :])


def forbidden_region_margin(paths: tuple[tuple[Point, ...], ...], obstacles: tuple[Point, ...]) -> float:
    if not obstacles:
        return 0.0
    return min(_distance(point, obstacle) for path in paths for point in path for obstacle in obstacles)


def symmetry_ambiguity_count(family_name: str, agent_count: int) -> int:
    profile = profile_for(family_name)
    scale = max(1, round(math.log2(agent_count + 1)))
    return profile.symmetry_base * scale


def base_target_bits(family_name: str, agent_count: int, grid_size: int = 64, time_steps: int = 24) -> float:
    profile = profile_for(family_name)
    endpoint_bits = math.log2(grid_size**3)
    path_bits = math.log2(max(2, time_steps)) if "path" in profile.features else 0.0
    topology_bits = 2.0 if "topology" in profile.features else 0.0
    forbidden_bits = 1.0 if "forbidden_region" in profile.features else 0.0
    role_bits = math.log2(max(2, agent_count)) if "role_binding" in profile.features else 0.0
    return round(endpoint_bits + path_bits + topology_bits + forbidden_bits + role_bits, 4)


def leakage_bits_lost(family_name: str, access_level: str, agent_count: int, trial_index: int) -> float:
    profile = profile_for(family_name)
    if access_level == "A0_public_only":
        return 0.0
    base = profile.leakage_one if access_level == "A2_one_stolen_agent" else profile.leakage_two
    scale = 1.0 + min(0.35, math.log2(agent_count) / 24)
    jitter = ((_stable_int("leakage_jitter", family_name, access_level, agent_count, trial_index) % 101) - 50) / 500
    return round(max(0.0, base * scale + jitter), 4)


def _endpoints(
    family_name: str, agents: tuple[str, ...], trial_index: int, grid_size: int
) -> dict[str, Point]:
    count = len(agents)
    center = grid_size // 2
    radius = max(6, min(grid_size // 3, 5 + count // 4))
    endpoints: dict[str, Point] = {}
    for index, agent in enumerate(agents):
        if family_name == "sphere_shell":
            theta = 2 * math.pi * index / count
            phi = math.acos(1 - 2 * (index + 0.5) / count)
            point = (
                center + round(radius * math.sin(phi) * math.cos(theta)),
                center + round(radius * math.sin(phi) * math.sin(theta)),
                center + round(radius * math.cos(phi)),
            )
        elif family_name == "helix":
            theta = 2 * math.pi * index / max(3, count)
            point = (
                center + round(radius * math.cos(theta)),
                center + round(radius * math.sin(theta)),
                4 + (index * max(1, grid_size - 8)) // max(1, count - 1),
            )
        elif family_name == "polytope":
            corners = _polytope_points(center, radius)
            base = corners[index % len(corners)]
            layer = index // len(corners)
            point = (
                _clamp(base[0] + layer * 2, grid_size),
                _clamp(base[1] + layer, grid_size),
                _clamp(base[2] + layer * 3, grid_size),
            )
        elif family_name == "braid":
            lane = index - count // 2
            point = (_clamp(center + lane * 2, grid_size), grid_size - 5, _clamp(8 + index % 7, grid_size))
        elif family_name == "voronoi":
            side = math.ceil(count ** (1 / 3))
            x = index % side
            y = (index // side) % side
            z = index // (side * side)
            spacing = max(4, (grid_size - 8) // max(1, side))
            point = (
                _clamp(4 + x * spacing + spacing // 2, grid_size),
                _clamp(4 + y * spacing + spacing // 2, grid_size),
                _clamp(4 + z * spacing + spacing // 2, grid_size),
            )
        else:
            side = math.ceil(count ** (1 / 3))
            spacing = max(3, (grid_size - 8) // max(1, side - 1))
            x = index % side
            y = (index // side) % side
            z = index // (side * side)
            point = (_clamp(4 + x * spacing, grid_size), _clamp(4 + y * spacing, grid_size), _clamp(4 + z * spacing, grid_size))
        salt = _stable_int("endpoint_salt", family_name, trial_index, agent) % 3
        endpoints[agent] = (_clamp(point[0] + salt - 1, grid_size), point[1], point[2])
    return endpoints


def _path(
    family_name: str,
    index: int,
    agent_count: int,
    endpoint: Point,
    trial_index: int,
    grid_size: int,
    time_steps: int,
    obstacles: tuple[Point, ...],
) -> tuple[Point, ...]:
    start = (_clamp(endpoint[0], grid_size), 1 + index % 5, _clamp(grid_size - 3 - index % 11, grid_size))
    if family_name == "helix":
        return tuple(
            (
                _clamp(endpoint[0] + round(6 * math.cos(2 * math.pi * (t / max(1, time_steps - 1)) + index)), grid_size),
                _clamp(endpoint[1] + round(6 * math.sin(2 * math.pi * (t / max(1, time_steps - 1)) + index)), grid_size),
                _clamp(round(start[2] + (endpoint[2] - start[2]) * t / max(1, time_steps - 1)), grid_size),
            )
            for t in range(time_steps - 1)
        ) + (endpoint,)
    if family_name == "obstacle_field":
        mid = (_clamp(endpoint[0] + 3 + index % 4, grid_size), _clamp(endpoint[1] + 6, grid_size), _clamp(endpoint[2] + 2, grid_size))
        return _two_segment_path(start, mid, endpoint, time_steps)
    if family_name == "braid":
        return tuple(
            (
                _clamp(round(start[0] + (endpoint[0] - start[0]) * t / max(1, time_steps - 1)), grid_size),
                _clamp(round(start[1] + (endpoint[1] - start[1]) * t / max(1, time_steps - 1)), grid_size),
                _clamp(endpoint[2] + ((-1) ** index) * round(3 * math.sin(math.pi * t / max(1, time_steps - 1))), grid_size),
            )
            for t in range(time_steps - 1)
        ) + (endpoint,)
    if family_name == "voronoi":
        mid = (_clamp(start[0], grid_size), _clamp(endpoint[1], grid_size), _clamp(start[2], grid_size))
        return _two_segment_path(start, mid, endpoint, time_steps)
    if family_name == "sphere_shell":
        outside = (_clamp(endpoint[0] + (3 if endpoint[0] < grid_size // 2 else -3), grid_size), start[1], start[2])
        return _two_segment_path(start, outside, endpoint, time_steps)
    if family_name == "polytope":
        mid = (_clamp(endpoint[0], grid_size), _clamp(start[1] + index % 3, grid_size), _clamp(endpoint[2], grid_size))
        return _two_segment_path(start, mid, endpoint, time_steps)
    return _linear_path(start, endpoint, time_steps)


def _obstacles(family_name: str, trial_index: int, grid_size: int) -> tuple[Point, ...]:
    if family_name not in {"obstacle_field", "braid", "voronoi"}:
        return ()
    count = {"obstacle_field": 18, "braid": 8, "voronoi": 24}[family_name]
    points = []
    for i in range(count):
        digest = _stable_int("obstacle", family_name, trial_index, i)
        points.append((4 + digest % (grid_size - 8), 4 + (digest // 97) % (grid_size - 8), 4 + (digest // 997) % (grid_size - 8)))
    return tuple(sorted(set(points)))


def _crossing_rules(family_name: str, trajectories: list[AgentTrajectory]) -> tuple[str, ...]:
    if family_name not in {"helix", "braid", "obstacle_field"}:
        return ()
    rules = []
    for left, right in zip(trajectories[::2], trajectories[1::2]):
        rules.append(f"{left.agent_id}<before<{right.agent_id}")
    return tuple(rules)


def _linear_path(start: Point, end: Point, steps: int) -> tuple[Point, ...]:
    if steps <= 1:
        return (end,)
    return tuple(
        (
            round(start[0] + (end[0] - start[0]) * t / (steps - 1)),
            round(start[1] + (end[1] - start[1]) * t / (steps - 1)),
            round(start[2] + (end[2] - start[2]) * t / (steps - 1)),
        )
        for t in range(steps)
    )


def _two_segment_path(start: Point, mid: Point, end: Point, steps: int) -> tuple[Point, ...]:
    first_steps = max(2, steps // 2)
    first = _linear_path(start, mid, first_steps)
    second = _linear_path(mid, end, steps - first_steps + 1)
    return first[:-1] + second


def _path_length(path: tuple[Point, ...]) -> float:
    return sum(_distance(a, b) for a, b in zip(path, path[1:]))


def _distance(a: Point, b: Point) -> float:
    return math.sqrt((a[0] - b[0]) ** 2 + (a[1] - b[1]) ** 2 + (a[2] - b[2]) ** 2)


def _clamp(value: int, grid_size: int) -> int:
    return max(0, min(grid_size - 1, int(value)))


def _polytope_points(center: int, radius: int) -> tuple[Point, ...]:
    return (
        (center - radius, center - radius, center - radius),
        (center - radius, center + radius, center + radius),
        (center + radius, center - radius, center + radius),
        (center + radius, center + radius, center - radius),
        (center - radius, center - radius, center + radius),
        (center + radius, center - radius, center - radius),
        (center - radius, center + radius, center - radius),
        (center + radius, center + radius, center + radius),
    )


def _digest_points(label: str, points: tuple[tuple[str, Point], ...]) -> str:
    return sha256_hex({"kind": f"geometry_feature_{label}", "points": [(a, list(p)) for a, p in points]})


def _stable_int(*parts: object) -> int:
    return int(sha256_hex({"kind": "geometry_lab_stable_int", "parts": parts})[:16], 16)
