"""Geometry-focused formation family lab.

This package deliberately sits beside the v2 coding-gate wrapper. It measures the
formation geometry layer only; the local wrapper architecture remains fixed.
"""

from .formation_spec import AgentTrajectory, FormationSpec
from .families import FAMILY_NAMES, generate_family_spec
from .verifier import GeometryVerifier, PresentedFormation, VerifierConfig

__all__ = [
    "AgentTrajectory",
    "FAMILY_NAMES",
    "FormationSpec",
    "GeometryVerifier",
    "PresentedFormation",
    "VerifierConfig",
    "generate_family_spec",
]
