"""Git remote guard."""

from __future__ import annotations

from .sandbox_spec import SandboxSpec


def git_remote_allowed(remote: str, spec: SandboxSpec) -> tuple[bool, str]:
    if remote not in spec.allowed_git_remotes:
        return False, "git_remote_not_allowed"
    if "://" in remote or remote.startswith("git@"):
        return False, "git_remote_not_allowed"
    return True, "ok"


def remote_is_network(remote: str) -> bool:
    return "://" in remote or remote.startswith("git@")
