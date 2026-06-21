"""Exact argv command policy."""

from __future__ import annotations

from dataclasses import dataclass

from .sandbox_spec import SandboxSpec

DANGEROUS_TOKENS = (
    ";",
    "&&",
    "|",
    "`",
    "$(",
    "rm",
    "curl",
    "wget",
    "bash",
    "sh",
    "cat .env",
    "pip",
)

ENV_FORBIDDEN_PREFIXES = ("GIT_", "SSH_")
ENV_FORBIDDEN_KEYS = {
    "PATH",
    "HOME",
    "PYTHONPATH",
    "LD_PRELOAD",
    "TOKEN",
    "API_KEY",
}


@dataclass(frozen=True)
class CommandDecision:
    allowed: bool
    reason: str
    command_id: str = ""


def command_id(args: tuple[str, ...]) -> str:
    if args == ("python", "-m", "unittest", "discover", "-s", "tests"):
        return "run_tests"
    if args == ("python", "scripts/safe_format.py"):
        return "safe_format"
    return " ".join(args)


def evaluate_command(args: tuple[str, ...], spec: SandboxSpec) -> CommandDecision:
    if args in spec.allowed_commands:
        return CommandDecision(True, "ok", command_id(args))
    joined = " ".join(args)
    if any(token in joined for token in DANGEROUS_TOKENS):
        return CommandDecision(False, "command_injection")
    if args and args[0] in {"bash", "sh", "curl", "wget", "rm"}:
        return CommandDecision(False, "command_not_allowed")
    if len(args) >= 2 and args[:2] == ("python", "-c"):
        return CommandDecision(False, "command_not_allowed")
    return CommandDecision(False, "command_not_allowed")


def env_locked(action_env: dict[str, str], spec: SandboxSpec) -> tuple[bool, str]:
    if not action_env:
        return True, "ok"
    for key in action_env:
        if key in ENV_FORBIDDEN_KEYS or any(key.startswith(prefix) for prefix in ENV_FORBIDDEN_PREFIXES):
            return False, "environment_not_fixed"
    merged = {**spec.allowed_env, **action_env}
    if merged != spec.allowed_env:
        return False, "environment_not_fixed"
    return True, "ok"
