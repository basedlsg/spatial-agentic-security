"""Attack definitions for geometry formation families."""

from __future__ import annotations

from dataclasses import dataclass

from spatial_swarm.spatial_puzzle.geometry_lab.verifier import PresentedFormation


@dataclass(frozen=True)
class AttackDefinition:
    name: str
    category: str
    violated_features: tuple[str, ...]
    families: tuple[str, ...] = ()
    description: str = ""

    def applies_to(self, family_name: str) -> bool:
        return not self.families or family_name in self.families


BASIC_ATTACKS = (
    AttackDefinition("endpoint_mutation", "basic", ("endpoint",), description="move one endpoint"),
    AttackDefinition("path_near_miss", "basic", ("path",), description="shift one path step"),
    AttackDefinition("collision_mutation", "basic", ("collision",), description="force a same-time collision"),
    AttackDefinition("path_crossing_mutation", "basic", ("path_crossing",), description="change crossing order"),
    AttackDefinition("forbidden_region_mutation", "basic", ("forbidden_region",), description="enter a forbidden zone"),
    AttackDefinition("wrong_final_formation", "basic", ("final_shape",), description="wrong final shape"),
    AttackDefinition("role_swap", "basic", ("role_binding",), description="swap two roles"),
    AttackDefinition("timing_shift", "basic", ("timing",), description="shift timing window"),
    AttackDefinition("delayed_agent", "basic", ("timing",), description="delay one agent"),
)

SOLVER_ATTACKS = (
    AttackDefinition("random_guess", "solver", ("endpoint", "path", "timing", "final_shape")),
    AttackDefinition("nearest_endpoint_guess", "solver", ("endpoint",)),
    AttackDefinition("shortest_path_guess", "solver", ("path",)),
    AttackDefinition("same_endpoint_wrong_path", "solver", ("path",)),
    AttackDefinition("same_path_wrong_timing", "solver", ("timing",)),
    AttackDefinition("collision_avoiding_guess", "solver", ("path",)),
    AttackDefinition("symmetry_guess", "solver", ("role_binding",)),
    AttackDefinition("topology_near_miss", "solver", ("topology",)),
)

GEOMETRY_SPECIFIC_ATTACKS = (
    AttackDefinition("same_radius_wrong_angle", "sphere", ("endpoint", "final_shape"), ("sphere_shell",)),
    AttackDefinition("antipodal_endpoint_swap", "sphere", ("role_binding", "final_shape"), ("sphere_shell",)),
    AttackDefinition("phase_shift", "helix", ("timing", "topology"), ("helix",)),
    AttackDefinition("same_endpoint_wrong_turn_count", "helix", ("path", "topology"), ("helix",)),
    AttackDefinition("edge_swap", "polytope", ("final_shape",), ("polytope",)),
    AttackDefinition("face_reflection", "polytope", ("role_binding", "final_shape"), ("polytope",)),
    AttackDefinition("symmetry_rotation", "polytope", ("role_binding",), ("polytope",)),
    AttackDefinition("shortcut_through_obstacle", "obstacle_field", ("forbidden_region",), ("obstacle_field",)),
    AttackDefinition("boundary_skimming_path", "obstacle_field", ("forbidden_region",), ("obstacle_field",)),
    AttackDefinition("wrong_crossing_order", "braid", ("path_crossing", "topology"), ("braid",)),
    AttackDefinition("same_endpoint_wrong_braid", "braid", ("topology",), ("braid",)),
    AttackDefinition("late_crossing_swap", "braid", ("timing", "topology"), ("braid",)),
    AttackDefinition("neighbor_cell_boundary_guess", "voronoi", ("forbidden_region",), ("voronoi",)),
    AttackDefinition("cell_centroid_guess", "voronoi", ("endpoint",), ("voronoi",)),
    AttackDefinition("stolen_neighbor_cell_inference", "voronoi", ("endpoint", "forbidden_region"), ("voronoi",)),
)

PARTIAL_COMPROMISE_LEVELS = (
    "A0_public_only",
    "A2_one_stolen_agent",
    "A3_two_stolen_agents",
)

MUTATION_TESTS = (
    AttackDefinition("move_endpoint_1_voxel", "rigidity", ("endpoint",)),
    AttackDefinition("move_endpoint_2_voxels", "rigidity", ("endpoint",)),
    AttackDefinition("shift_one_path_step", "rigidity", ("path",)),
    AttackDefinition("shift_one_timing_step", "rigidity", ("timing",)),
    AttackDefinition("swap_two_roles", "rigidity", ("role_binding",)),
    AttackDefinition("mirror_formation", "rigidity", ("final_shape", "role_binding")),
    AttackDefinition("rotate_final_formation", "rigidity", ("final_shape", "role_binding")),
    AttackDefinition("remove_path_segment", "rigidity", ("path",)),
    AttackDefinition("replace_curve_with_shortest_path", "rigidity", ("path", "topology")),
)

SYMMETRY_TESTS = (
    AttackDefinition("rotate_final_shape", "symmetry", ("final_shape", "role_binding")),
    AttackDefinition("reflect_final_shape", "symmetry", ("final_shape", "role_binding")),
    AttackDefinition("swap_symmetric_roles", "symmetry", ("role_binding",)),
    AttackDefinition("permute_equal_distance_endpoints", "symmetry", ("endpoint", "role_binding")),
)

TOPOLOGY_TESTS = (
    AttackDefinition("same_endpoint_different_route", "topology", ("path", "topology"), ("braid",)),
    AttackDefinition("same_route_different_crossing_order", "topology", ("path_crossing", "topology"), ("braid",)),
    AttackDefinition("same_crossing_order_wrong_timing", "topology", ("timing",), ("braid",)),
    AttackDefinition("same_final_shape_wrong_topology", "topology", ("topology",), ("braid",)),
)


def attack_suite_for_family(family_name: str) -> tuple[AttackDefinition, ...]:
    return tuple(
        attack
        for attack in BASIC_ATTACKS + SOLVER_ATTACKS + GEOMETRY_SPECIFIC_ATTACKS
        if attack.applies_to(family_name)
    )


def mutate_for_attack(presented: PresentedFormation, attack: AttackDefinition, trial_index: int) -> PresentedFormation:
    return presented.with_mutated_features(
        attack.violated_features,
        f"{attack.category}:{attack.name}:{trial_index}",
    )
