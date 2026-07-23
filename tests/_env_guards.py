"""Shared skip guards for environment-dependent integration tests.

Some tests in this repo exercise external resources that are not present in a bare
CI/dev environment:

- Docker sandbox tests need a running Docker daemon and the sandbox container image.
- Persistent model-worker (MLX) tests spawn a subprocess worker that needs a compatible
  environment; they are opt-in via SPATIAL_RUN_WORKER_TESTS=1.

These guards make `pytest` green in a bare environment while still running the tests where
the resource is available. They gate other research lines on this branch, not the
spatial-security arc.
"""

from __future__ import annotations

import os

import pytest


def docker_available() -> bool:
    try:
        from spatial_swarm.spatial_puzzle.experiments import real_sandbox_gate_v3 as V3

        return bool(V3._docker_info().get("available", False))
    except Exception:
        return False


needs_docker = pytest.mark.skipif(
    not docker_available(),
    reason="requires a working Docker sandbox backend + container image",
)

needs_worker = pytest.mark.skipif(
    not os.environ.get("SPATIAL_RUN_WORKER_TESTS"),
    reason="persistent model-worker integration test; set SPATIAL_RUN_WORKER_TESTS=1 to run",
)
