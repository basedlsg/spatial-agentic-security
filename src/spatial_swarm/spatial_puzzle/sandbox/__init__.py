"""Contained execution helpers for Real Sandbox Gate v3."""

from .container_adapter import ContainerAdapter
from .results import EffectRecord, SandboxRunResult
from .sandbox_spec import SandboxSpec

__all__ = ["ContainerAdapter", "EffectRecord", "SandboxRunResult", "SandboxSpec"]
