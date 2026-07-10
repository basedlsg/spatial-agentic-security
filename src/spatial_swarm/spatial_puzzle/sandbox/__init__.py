"""Contained execution helpers for Real Sandbox Gate v3."""

from .content_bound import (
    ActionEnvelopeV4,
    ContentBindingError,
    ContentBoundActionBuilder,
    ContentBoundExecutionResult,
    ContentBoundExecutor,
    ExactPatch,
    PatchManifestEntry,
    PatchOperation,
)
from .container_adapter import ContainerAdapter
from .results import EffectRecord, SandboxRunResult
from .sandbox_spec import SandboxSpec

__all__ = [
    "ActionEnvelopeV4",
    "ContentBindingError",
    "ContentBoundActionBuilder",
    "ContentBoundExecutionResult",
    "ContentBoundExecutor",
    "ContainerAdapter",
    "EffectRecord",
    "ExactPatch",
    "PatchManifestEntry",
    "PatchOperation",
    "SandboxRunResult",
    "SandboxSpec",
]
