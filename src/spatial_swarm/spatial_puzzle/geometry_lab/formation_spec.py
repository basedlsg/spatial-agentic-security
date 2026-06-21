"""Shared geometry formation objects."""

from __future__ import annotations

from dataclasses import dataclass

from spatial_swarm.crypto.hashing import sha256_hex

Point = tuple[int, int, int]


@dataclass(frozen=True)
class AgentTrajectory:
    agent_id: str
    role: str
    start_point: Point
    endpoint: Point
    path: tuple[Point, ...]
    timing_window: tuple[int, int]
    private_digest: str

    def canonical(self) -> dict:
        return {
            "agent_id": self.agent_id,
            "role": self.role,
            "start_point": list(self.start_point),
            "endpoint": list(self.endpoint),
            "path": [list(point) for point in self.path],
            "timing_window": list(self.timing_window),
            "private_digest": self.private_digest,
        }


@dataclass(frozen=True)
class FormationSpec:
    family_name: str
    agent_ids: tuple[str, ...]
    action_hash: str
    nonce: str
    risk_level: str
    grid_size: int
    time_steps: int
    endpoints: tuple[tuple[str, Point], ...]
    paths: tuple[tuple[str, tuple[Point, ...]], ...]
    role_map: tuple[tuple[str, str], ...]
    obstacle_map: tuple[Point, ...]
    collision_rules: tuple[tuple[str, str], ...]
    crossing_rules: tuple[str, ...]
    final_shape_signature: str
    topology_signature: str
    trajectories: tuple[AgentTrajectory, ...]
    feature_signatures: tuple[tuple[str, str], ...]

    def endpoint_for(self, agent_id: str) -> Point:
        return dict(self.endpoints)[agent_id]

    def path_for(self, agent_id: str) -> tuple[Point, ...]:
        return dict(self.paths)[agent_id]

    def role_for(self, agent_id: str) -> str:
        return dict(self.role_map)[agent_id]

    def signature(self, feature: str) -> str:
        return dict(self.feature_signatures)[feature]

    def signatures(self) -> dict[str, str]:
        return dict(self.feature_signatures)

    def canonical_public(self) -> dict:
        return {
            "family_name": self.family_name,
            "agent_ids": list(self.agent_ids),
            "action_hash": self.action_hash,
            "nonce": self.nonce,
            "risk_level": self.risk_level,
            "grid_size": self.grid_size,
            "time_steps": self.time_steps,
            "endpoints": [(agent, list(point)) for agent, point in self.endpoints],
            "role_map": list(self.role_map),
            "obstacle_count": len(self.obstacle_map),
            "collision_rules": list(self.collision_rules),
            "crossing_rules": list(self.crossing_rules),
            "final_shape_signature": self.final_shape_signature,
            "topology_signature": self.topology_signature,
            "feature_signatures": list(self.feature_signatures),
        }

    def public_digest(self) -> str:
        return sha256_hex({"kind": "geometry_formation_public", "spec": self.canonical_public()})


def agent_ids(agent_count: int) -> tuple[str, ...]:
    return tuple(f"agent_{index + 1:03d}" for index in range(agent_count))


def role_for_index(index: int) -> str:
    roles = ("planner", "coder", "tester", "security", "repo_guardian")
    return roles[index % len(roles)]
