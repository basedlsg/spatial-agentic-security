"""Sandbox policy specification."""

from __future__ import annotations

from dataclasses import dataclass, field

from spatial_swarm.crypto.hashing import sha256_hex

DEFAULT_ENV = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/tmp/sandbox_home",
    "PYTHONPATH": "",
    "GIT_CONFIG_GLOBAL": "/dev/null",
    "PYTHONDONTWRITEBYTECODE": "1",
}

DEFAULT_ALLOWED_COMMANDS = (
    ("python", "-m", "unittest", "discover", "-s", "tests"),
    ("python", "scripts/safe_format.py"),
)


@dataclass(frozen=True)
class SandboxSpec:
    sandbox_id: str = "real-sandbox-gate-v3"
    repo_template: str = "toy_repo_v3"
    working_directory: str = "/workspace/repo"
    read_only_paths: tuple[str, ...] = ("README.md", "src/app.py", "tests/test_app.py")
    writable_paths: tuple[str, ...] = (
        "src/app.py",
        "tmp/output.log",
        "vendor/demo_tool.dist-info/INSTALLER",
        "vendor/demo_tool.dist-info",
    )
    allowed_commands: tuple[tuple[str, ...], ...] = DEFAULT_ALLOWED_COMMANDS
    allowed_env: dict[str, str] = field(default_factory=lambda: dict(DEFAULT_ENV))
    network_mode: str = "off"
    allowed_git_remotes: tuple[str, ...] = ("local-origin",)
    allowed_credential_handles: tuple[str, ...] = ("TEST_DB_READONLY", "CI_DEPLOY_HANDLE")
    timeout_ms: int = 15000
    memory_limit_mb: int = 256
    cpu_limit: float = 1.0
    max_output_bytes: int = 8192
    container_image: str = "slop-code:python3.12"

    def env_digest(self) -> str:
        return sha256_hex({"kind": "sandbox_allowed_env_v3", "env": self.allowed_env})

    def env_items(self) -> tuple[str, ...]:
        return tuple(f"{key}={value}" for key, value in sorted(self.allowed_env.items()))
