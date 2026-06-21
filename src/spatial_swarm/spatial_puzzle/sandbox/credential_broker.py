"""Fake credential broker for contained execution tests."""

from __future__ import annotations

from dataclasses import dataclass

from spatial_swarm.crypto.hashing import sha256_hex

from .sandbox_spec import SandboxSpec


@dataclass(frozen=True)
class CredentialResponse:
    handle: str
    digest: str
    raw_value_revealed: bool = False


class FakeCredentialBroker:
    def __init__(self, spec: SandboxSpec) -> None:
        self._handles = {
            handle: f"fake_secret_value_for_{handle}"
            for handle in spec.allowed_credential_handles
        }

    def request_digest(self, handle: str) -> CredentialResponse:
        if handle not in self._handles:
            raise KeyError(handle)
        return CredentialResponse(
            handle=handle,
            digest=sha256_hex({"kind": "fake_credential_digest", "handle": handle}),
        )

    def raw_value_for_attack(self, handle: str) -> str:
        return self._handles.get(handle, "")
