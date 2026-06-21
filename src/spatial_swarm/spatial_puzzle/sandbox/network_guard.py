"""Network guard for Docker-backed sandboxes."""

from __future__ import annotations

NETWORK_TOKENS = ("curl", "wget", "socket", "pip", "https://", "ssh://", "git@")


def docker_network_args(network_mode: str) -> tuple[str, ...]:
    if network_mode == "off":
        return ("--network", "none")
    return ("--network", "bridge")


def command_attempts_network(args: tuple[str, ...]) -> bool:
    joined = " ".join(args).lower()
    return any(token in joined for token in NETWORK_TOKENS)
