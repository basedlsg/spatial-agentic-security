"""Geometry verifier and ablation switches."""

from __future__ import annotations

from dataclasses import dataclass, replace

from spatial_swarm.crypto.hashing import sha256_hex
from spatial_swarm.spatial_puzzle.geometry_lab.families import FEATURES, estimated_runtime_ms, profile_for
from spatial_swarm.spatial_puzzle.geometry_lab.formation_spec import FormationSpec


@dataclass(frozen=True)
class PresentedFormation:
    family_name: str
    agent_ids: tuple[str, ...]
    action_hash: str
    nonce: str
    feature_signatures: tuple[tuple[str, str], ...]

    @classmethod
    def from_spec(cls, spec: FormationSpec) -> "PresentedFormation":
        return cls(
            family_name=spec.family_name,
            agent_ids=spec.agent_ids,
            action_hash=spec.action_hash,
            nonce=spec.nonce,
            feature_signatures=spec.feature_signatures,
        )

    def signature(self, feature: str) -> str:
        return dict(self.feature_signatures)[feature]

    def with_mutated_features(self, features: tuple[str, ...], label: str) -> "PresentedFormation":
        signatures = dict(self.feature_signatures)
        for feature in features:
            signatures[feature] = sha256_hex(
                {
                    "kind": "mutated_geometry_feature",
                    "family": self.family_name,
                    "feature": feature,
                    "label": label,
                    "old": signatures.get(feature, ""),
                }
            )
        return replace(self, feature_signatures=tuple(sorted(signatures.items())))


@dataclass(frozen=True)
class VerifierConfig:
    check_endpoint: bool = True
    check_path: bool = True
    check_timing: bool = True
    check_collision: bool = True
    check_forbidden_region: bool = True
    check_path_crossing: bool = True
    check_final_shape: bool = True
    check_role_binding: bool = True
    check_topology: bool = True

    def enabled(self, feature: str) -> bool:
        return bool(getattr(self, f"check_{feature}"))


FULL_GEOMETRY = VerifierConfig()

BASELINE_CONFIGS: dict[str, VerifierConfig] = {
    "hmac_only": VerifierConfig(
        check_endpoint=False,
        check_path=False,
        check_timing=False,
        check_collision=False,
        check_forbidden_region=False,
        check_path_crossing=False,
        check_final_shape=False,
        check_role_binding=False,
        check_topology=False,
    ),
    "endpoint_only": VerifierConfig(
        check_path=False,
        check_timing=False,
        check_collision=False,
        check_forbidden_region=False,
        check_path_crossing=False,
        check_final_shape=False,
        check_role_binding=False,
        check_topology=False,
    ),
    "endpoint_path": VerifierConfig(
        check_timing=False,
        check_collision=False,
        check_forbidden_region=False,
        check_path_crossing=False,
        check_final_shape=False,
        check_role_binding=False,
        check_topology=False,
    ),
    "endpoint_path_collision": VerifierConfig(
        check_timing=False,
        check_forbidden_region=False,
        check_path_crossing=False,
        check_final_shape=False,
        check_role_binding=False,
        check_topology=False,
    ),
    "endpoint_path_collision_final": VerifierConfig(
        check_timing=False,
        check_forbidden_region=False,
        check_path_crossing=False,
        check_role_binding=False,
        check_topology=False,
    ),
    "current_full_gate": VerifierConfig(check_topology=False),
    "full_geometry": FULL_GEOMETRY,
}

ABLATION_CONFIGS: dict[str, VerifierConfig] = {
    "full_geometry": FULL_GEOMETRY,
    "no_endpoint": replace(FULL_GEOMETRY, check_endpoint=False),
    "no_path": replace(FULL_GEOMETRY, check_path=False),
    "no_timing": replace(FULL_GEOMETRY, check_timing=False),
    "no_collision": replace(FULL_GEOMETRY, check_collision=False),
    "no_path_crossing": replace(FULL_GEOMETRY, check_path_crossing=False),
    "no_forbidden_region": replace(FULL_GEOMETRY, check_forbidden_region=False),
    "no_final_shape": replace(FULL_GEOMETRY, check_final_shape=False),
    "no_role_binding": replace(FULL_GEOMETRY, check_role_binding=False),
    "no_topology": replace(FULL_GEOMETRY, check_topology=False),
}


@dataclass(frozen=True)
class GeometryDecision:
    released: bool
    blocked: bool
    internal_reasons: tuple[str, ...]
    checks_performed: int
    verification_runtime_ms: float


class GeometryVerifier:
    def __init__(self, config: VerifierConfig = FULL_GEOMETRY) -> None:
        self.config = config

    def verify(self, spec: FormationSpec, presented: PresentedFormation) -> GeometryDecision:
        profile = profile_for(spec.family_name)
        reasons: list[str] = []
        checks = 0
        if presented.family_name != spec.family_name:
            reasons.append("wrong_family")
        if presented.action_hash != spec.action_hash:
            reasons.append("wrong_action_hash")
        if presented.nonce != spec.nonce:
            reasons.append("wrong_nonce")
        checks += 3
        for feature in FEATURES:
            if not self.config.enabled(feature):
                continue
            if feature not in profile.features:
                continue
            checks += 1
            if presented.signature(feature) != spec.signature(feature):
                reasons.append(f"wrong_{feature}")
        return GeometryDecision(
            released=not reasons,
            blocked=bool(reasons),
            internal_reasons=tuple(sorted(set(reasons))),
            checks_performed=checks,
            verification_runtime_ms=estimated_runtime_ms(
                spec.family_name, len(spec.agent_ids), spec.time_steps
            ),
        )


def config_for_ablation(name: str) -> VerifierConfig:
    try:
        return ABLATION_CONFIGS[name]
    except KeyError as exc:
        raise ValueError(f"unknown ablation: {name}") from exc


def config_for_baseline(name: str) -> VerifierConfig:
    try:
        return BASELINE_CONFIGS[name]
    except KeyError as exc:
        raise ValueError(f"unknown baseline: {name}") from exc
