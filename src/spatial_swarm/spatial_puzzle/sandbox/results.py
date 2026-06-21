"""Sandbox execution result objects."""

from __future__ import annotations

from dataclasses import dataclass, field

from spatial_swarm.crypto.hashing import sha256_hex


@dataclass(frozen=True)
class EffectRecord:
    files_read: tuple[str, ...] = ()
    files_written: tuple[str, ...] = ()
    files_deleted: tuple[str, ...] = ()
    files_created: tuple[str, ...] = ()
    commands_run: tuple[str, ...] = ()
    subprocesses_spawned: int = 0
    network_attempts: int = 0
    credentials_requested: tuple[str, ...] = ()
    git_remotes_touched: tuple[str, ...] = ()
    environment_used: tuple[str, ...] = ()
    working_directory_used: str = ""
    stdout_digest: str = ""
    stderr_digest: str = ""
    exit_code: int = 0

    def canonical(self) -> dict:
        return {
            "files_read": list(self.files_read),
            "files_written": list(self.files_written),
            "files_deleted": list(self.files_deleted),
            "files_created": list(self.files_created),
            "commands_run": list(self.commands_run),
            "subprocesses_spawned": self.subprocesses_spawned,
            "network_attempts": self.network_attempts,
            "credentials_requested": list(self.credentials_requested),
            "git_remotes_touched": list(self.git_remotes_touched),
            "environment_used": list(self.environment_used),
            "working_directory_used": self.working_directory_used,
            "stdout_digest": self.stdout_digest,
            "stderr_digest": self.stderr_digest,
            "exit_code": self.exit_code,
        }

    def digest(self) -> str:
        return sha256_hex({"kind": "sandbox_effect_record_v3", "effect": self.canonical()})

    def merge(self, other: "EffectRecord") -> "EffectRecord":
        return EffectRecord(
            files_read=_sorted_union(self.files_read, other.files_read),
            files_written=_sorted_union(self.files_written, other.files_written),
            files_deleted=_sorted_union(self.files_deleted, other.files_deleted),
            files_created=_sorted_union(self.files_created, other.files_created),
            commands_run=_sorted_union(self.commands_run, other.commands_run),
            subprocesses_spawned=max(self.subprocesses_spawned, other.subprocesses_spawned),
            network_attempts=self.network_attempts + other.network_attempts,
            credentials_requested=_sorted_union(
                self.credentials_requested, other.credentials_requested
            ),
            git_remotes_touched=_sorted_union(
                self.git_remotes_touched, other.git_remotes_touched
            ),
            environment_used=self.environment_used or other.environment_used,
            working_directory_used=self.working_directory_used or other.working_directory_used,
            stdout_digest=self.stdout_digest or other.stdout_digest,
            stderr_digest=self.stderr_digest or other.stderr_digest,
            exit_code=max(self.exit_code, other.exit_code),
        )

    def exceeds(self, allowed: "EffectRecord") -> bool:
        return (
            not set(self.files_read).issubset(allowed.files_read)
            or not set(self.files_written).issubset(allowed.files_written)
            or not set(self.files_deleted).issubset(allowed.files_deleted)
            or not set(self.files_created).issubset(allowed.files_created)
            or not set(self.commands_run).issubset(allowed.commands_run)
            or self.subprocesses_spawned > allowed.subprocesses_spawned
            or self.network_attempts > allowed.network_attempts
            or not set(self.credentials_requested).issubset(allowed.credentials_requested)
            or not set(self.git_remotes_touched).issubset(allowed.git_remotes_touched)
            or (
                bool(allowed.environment_used)
                and tuple(self.environment_used) != tuple(allowed.environment_used)
            )
            or (
                bool(allowed.working_directory_used)
                and self.working_directory_used != allowed.working_directory_used
            )
            or (allowed.exit_code == 0 and self.exit_code != 0)
        )


@dataclass(frozen=True)
class SandboxRunResult:
    executed: bool
    blocked: bool
    effect_violation: bool
    actual_effects: EffectRecord
    allowed_effects: EffectRecord
    stdout: str = ""
    stderr: str = ""
    internal_reasons: tuple[str, ...] = ()
    container_backend: str = "docker"
    host_effects_detected: int = 0
    raw_credential_leaked: bool = False


def digest_bytes(data: bytes) -> str:
    return sha256_hex({"kind": "sandbox_stream_digest", "sha256": __import__("hashlib").sha256(data).hexdigest()})


def _sorted_union(left: tuple[str, ...], right: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(sorted(set(left).union(right)))
