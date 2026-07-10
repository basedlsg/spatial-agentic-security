"""Content-bound action envelopes and disposable exact-patch execution.

V3 binds an action type, target path, and structural effects. This module adds the
missing byte-level binding required for live coding-agent experiments: reviewers
authorize an exact patch against an exact repository prestate, and only the resulting
verified poststate is eligible for promotion.
"""

from __future__ import annotations

import hashlib
import shutil
import tempfile
import unicodedata
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from typing import Callable, Optional

from spatial_swarm.crypto.hashing import sha256_hex

from .effect_tracer import effect_from_delta
from .filesystem_snapshot import FilesystemSnapshot, diff, snapshot
from .results import EffectRecord


PATCH_OPERATIONS = frozenset({"create", "replace", "delete"})
NO_TRANSACTION_DIGEST = "no-transaction"


class ContentBindingError(ValueError):
    """Raised when a patch cannot be represented safely and canonically."""


@dataclass(frozen=True)
class PatchOperation:
    """One exact file operation proposed by a coding agent."""

    path: str
    operation: str
    content: bytes = field(default=b"", repr=False)

    def __post_init__(self) -> None:
        if self.operation not in PATCH_OPERATIONS:
            raise ContentBindingError(f"unsupported patch operation: {self.operation}")
        if not isinstance(self.content, bytes):
            raise ContentBindingError("patch content must be bytes")
        if self.operation == "delete" and self.content:
            raise ContentBindingError("delete operations cannot carry replacement content")

    @classmethod
    def create(cls, path: str, content: bytes) -> "PatchOperation":
        return cls(path=path, operation="create", content=content)

    @classmethod
    def replace(cls, path: str, content: bytes) -> "PatchOperation":
        return cls(path=path, operation="replace", content=content)

    @classmethod
    def delete(cls, path: str) -> "PatchOperation":
        return cls(path=path, operation="delete")


@dataclass(frozen=True)
class ExactPatch:
    """A deterministic set of exact file operations."""

    operations: tuple[PatchOperation, ...]

    def __post_init__(self) -> None:
        if not self.operations:
            raise ContentBindingError("an exact patch must contain at least one operation")


@dataclass(frozen=True)
class PatchManifestEntry:
    """Public byte-level commitment for one patch operation."""

    path: str
    operation: str
    old_sha256: str
    new_sha256: str
    new_size: int

    def canonical(self) -> dict[str, object]:
        return {
            "path": self.path,
            "operation": self.operation,
            "old_sha256": self.old_sha256,
            "new_sha256": self.new_sha256,
            "new_size": self.new_size,
        }


@dataclass(frozen=True)
class ActionEnvelopeV4:
    """Authorization envelope for one exact repository transition."""

    task_id: str
    trusted_user_intent_digest: str
    repository_prestate_digest: str
    action_type: str
    canonical_patch_digest: str
    patch_manifest: tuple[PatchManifestEntry, ...]
    expected_poststate_digest: str
    risk_level: str
    required_agent_set: tuple[str, ...]
    allowed_effects: EffectRecord
    allowed_effects_digest: str
    transaction_digest: str
    nonce: str
    action_hash: str

    def canonical_body(self) -> dict[str, object]:
        return {
            "kind": "content_bound_action_envelope_v4",
            "task_id": self.task_id,
            "trusted_user_intent_digest": self.trusted_user_intent_digest,
            "repository_prestate_digest": self.repository_prestate_digest,
            "action_type": self.action_type,
            "canonical_patch_digest": self.canonical_patch_digest,
            "patch_manifest": [entry.canonical() for entry in self.patch_manifest],
            "expected_poststate_digest": self.expected_poststate_digest,
            "risk_level": self.risk_level,
            "required_agent_set": list(self.required_agent_set),
            "allowed_effects_digest": self.allowed_effects_digest,
            "transaction_digest": self.transaction_digest,
            "nonce": self.nonce,
        }

    def computed_action_hash(self) -> str:
        return sha256_hex(self.canonical_body())

    def self_consistent(self) -> bool:
        return (
            self.canonical_patch_digest == _manifest_digest(self.patch_manifest)
            and self.allowed_effects_digest == self.allowed_effects.digest()
            and self.action_hash == self.computed_action_hash()
            and len(self.required_agent_set) == len(set(self.required_agent_set))
            and bool(self.required_agent_set)
        )


@dataclass(frozen=True)
class ContentBoundExecutionResult:
    """Verdict for execution inside a disposable victim replica."""

    applied: bool
    promotable: bool
    blocked: bool
    reason: str
    actual_effects: EffectRecord = field(default_factory=EffectRecord)
    actual_poststate_digest: str = ""
    source_repository_unchanged: bool = True
    oracle_passed: bool = True

    @property
    def released(self) -> bool:
        return self.promotable

    @property
    def harm_observed(self) -> bool:
        return not self.oracle_passed


class ContentBoundActionBuilder:
    """Build V4 envelopes from a trusted repository prestate and exact patch bytes."""

    def __init__(self, repository: Path) -> None:
        self.repository = repository.resolve()
        if not self.repository.is_dir():
            raise ContentBindingError("repository must be an existing directory")

    def build(
        self,
        patch: ExactPatch,
        *,
        task_id: str,
        trusted_user_intent: str,
        risk_level: str,
        required_agent_set: tuple[str, ...],
        transaction_digest: str = NO_TRANSACTION_DIGEST,
        nonce_label: str = "0",
    ) -> ActionEnvelopeV4:
        if not task_id:
            raise ContentBindingError("task_id is required")
        if not trusted_user_intent:
            raise ContentBindingError("trusted user intent is required")
        if not required_agent_set or len(required_agent_set) != len(set(required_agent_set)):
            raise ContentBindingError("required agents must be non-empty and unique")

        prestate = snapshot(self.repository)
        prestate_digest = _snapshot_digest(prestate)
        canonical_operations = _canonical_operations(self.repository, patch)
        manifest = _manifest(self.repository, canonical_operations)
        allowed_effects = _allowed_effects(manifest)
        patch_digest = _manifest_digest(manifest)
        expected_poststate = _expected_poststate_digest(
            self.repository,
            canonical_operations,
        )
        intent_digest = sha256_hex(
            {"kind": "trusted_user_intent_v4", "intent": trusted_user_intent}
        )
        nonce = sha256_hex(
            {
                "kind": "content_bound_nonce_v4",
                "task_id": task_id,
                "intent_digest": intent_digest,
                "prestate_digest": prestate_digest,
                "patch_digest": patch_digest,
                "label": nonce_label,
            }
        )[:32]
        envelope = ActionEnvelopeV4(
            task_id=task_id,
            trusted_user_intent_digest=intent_digest,
            repository_prestate_digest=prestate_digest,
            action_type="apply_exact_patch",
            canonical_patch_digest=patch_digest,
            patch_manifest=manifest,
            expected_poststate_digest=expected_poststate,
            risk_level=risk_level,
            required_agent_set=required_agent_set,
            allowed_effects=allowed_effects,
            allowed_effects_digest=allowed_effects.digest(),
            transaction_digest=transaction_digest,
            nonce=nonce,
            action_hash="",
        )
        envelope = replace(envelope, action_hash=envelope.computed_action_hash())
        if not envelope.self_consistent():
            raise ContentBindingError("constructed envelope is not self-consistent")
        return envelope


class ContentBoundExecutor:
    """Apply approved bytes only inside a fresh disposable repository replica."""

    def execute(
        self,
        source_repository: Path,
        envelope: ActionEnvelopeV4,
        patch: ExactPatch,
        *,
        safety_oracle: Optional[Callable[[Path], bool]] = None,
        enforce_safety_oracle: bool = False,
    ) -> ContentBoundExecutionResult:
        source = source_repository.resolve()
        source_before = _snapshot_digest(snapshot(source))
        if not envelope.self_consistent():
            return _blocked("invalid_envelope", source, source_before)
        if source_before != envelope.repository_prestate_digest:
            return _blocked("repository_prestate_mismatch", source, source_before)

        try:
            canonical_operations = _canonical_operations(source, patch)
            manifest = _manifest(source, canonical_operations)
        except ContentBindingError:
            return _blocked("invalid_patch", source, source_before)
        if manifest != envelope.patch_manifest:
            return _blocked("patch_manifest_mismatch", source, source_before)
        if _manifest_digest(manifest) != envelope.canonical_patch_digest:
            return _blocked("patch_digest_mismatch", source, source_before)

        with tempfile.TemporaryDirectory(prefix="content-bound-v4-") as tmp:
            staged = Path(tmp) / "repo"
            shutil.copytree(source, staged, symlinks=True)
            before = snapshot(staged)
            _apply_operations(staged, canonical_operations)
            after = snapshot(staged)
            effects = effect_from_delta(diff(before, after))
            poststate_digest = _snapshot_digest(after)
            oracle_passed = True if safety_oracle is None else bool(safety_oracle(staged))
            reason = "ok"
            promotable = True
            if effects.digest() != envelope.allowed_effects_digest:
                reason = "effect_mismatch"
                promotable = False
            elif poststate_digest != envelope.expected_poststate_digest:
                reason = "poststate_mismatch"
                promotable = False
            elif not oracle_passed and enforce_safety_oracle:
                reason = "harm_oracle_failed"
                promotable = False

        source_after = _snapshot_digest(snapshot(source))
        return ContentBoundExecutionResult(
            applied=True,
            promotable=promotable,
            blocked=not promotable,
            reason=reason,
            actual_effects=effects,
            actual_poststate_digest=poststate_digest,
            source_repository_unchanged=source_after == source_before,
            oracle_passed=oracle_passed,
        )


def _blocked(reason: str, source: Path, source_before: str) -> ContentBoundExecutionResult:
    source_after = _snapshot_digest(snapshot(source))
    return ContentBoundExecutionResult(
        applied=False,
        promotable=False,
        blocked=True,
        reason=reason,
        source_repository_unchanged=source_after == source_before,
    )


def _canonical_operations(
    repository: Path,
    patch: ExactPatch,
) -> tuple[tuple[str, PatchOperation], ...]:
    canonical: list[tuple[str, PatchOperation]] = []
    seen: set[str] = set()
    for operation in patch.operations:
        path = _canonical_patch_path(repository, operation.path)
        if path in seen:
            raise ContentBindingError(f"duplicate patch path: {path}")
        seen.add(path)
        target = repository / path
        exists = target.exists() or target.is_symlink()
        if operation.operation == "create" and exists:
            raise ContentBindingError(f"create target already exists: {path}")
        if operation.operation in {"replace", "delete"}:
            if not exists or not target.is_file() or target.is_symlink():
                raise ContentBindingError(f"patch target is not a regular file: {path}")
        canonical.append((path, operation))
    return tuple(sorted(canonical, key=lambda item: item[0]))


def _canonical_patch_path(repository: Path, raw_path: str) -> str:
    normalized = unicodedata.normalize("NFC", raw_path)
    if not normalized or any(char in normalized for char in "*?[]"):
        raise ContentBindingError("patch path is empty or contains a glob")
    pure = PurePosixPath(normalized)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ContentBindingError("patch path must be a canonical relative path")
    if any(part in {".git", "__pycache__"} for part in pure.parts):
        raise ContentBindingError("patch path targets excluded repository metadata")
    if pure.suffix in {".pyc", ".pyo"}:
        raise ContentBindingError("patch path targets an ignored bytecode file")

    current = repository
    for part in pure.parts:
        current = current / part
        if current.is_symlink():
            raise ContentBindingError("patch path traverses a symlink")
    try:
        current.resolve(strict=False).relative_to(repository.resolve())
    except ValueError as exc:
        raise ContentBindingError("patch path escapes repository") from exc
    return pure.as_posix()


def _manifest(
    repository: Path,
    operations: tuple[tuple[str, PatchOperation], ...],
) -> tuple[PatchManifestEntry, ...]:
    entries = []
    for path, operation in operations:
        target = repository / path
        old_sha256 = _file_sha256(target) if operation.operation != "create" else ""
        new_sha256 = _bytes_sha256(operation.content) if operation.operation != "delete" else ""
        entries.append(
            PatchManifestEntry(
                path=path,
                operation=operation.operation,
                old_sha256=old_sha256,
                new_sha256=new_sha256,
                new_size=len(operation.content) if operation.operation != "delete" else 0,
            )
        )
    return tuple(entries)


def _manifest_digest(manifest: tuple[PatchManifestEntry, ...]) -> str:
    return sha256_hex(
        {
            "kind": "exact_patch_manifest_v4",
            "entries": [entry.canonical() for entry in manifest],
        }
    )


def _allowed_effects(manifest: tuple[PatchManifestEntry, ...]) -> EffectRecord:
    return EffectRecord(
        files_written=tuple(entry.path for entry in manifest if entry.operation == "replace"),
        files_created=tuple(entry.path for entry in manifest if entry.operation == "create"),
        files_deleted=tuple(entry.path for entry in manifest if entry.operation == "delete"),
    )


def _expected_poststate_digest(
    repository: Path,
    operations: tuple[tuple[str, PatchOperation], ...],
) -> str:
    with tempfile.TemporaryDirectory(prefix="content-bound-v4-build-") as tmp:
        staged = Path(tmp) / "repo"
        shutil.copytree(repository, staged, symlinks=True)
        _apply_operations(staged, operations)
        return _snapshot_digest(snapshot(staged))


def _apply_operations(
    repository: Path,
    operations: tuple[tuple[str, PatchOperation], ...],
) -> None:
    for path, operation in operations:
        target = repository / path
        if operation.operation == "create":
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(operation.content)
        elif operation.operation == "replace":
            target.write_bytes(operation.content)
        elif operation.operation == "delete":
            target.unlink()
        else:  # pragma: no cover - PatchOperation rejects this at construction.
            raise ContentBindingError(f"unsupported patch operation: {operation.operation}")


def _snapshot_digest(state: FilesystemSnapshot) -> str:
    return sha256_hex(
        {
            "kind": "repository_snapshot_v4",
            "files": [
                {
                    "path": path,
                    "kind": file_state.kind,
                    "digest": file_state.digest,
                    "mode": file_state.mode,
                    "target": file_state.target,
                }
                for path, file_state in sorted(state.files.items())
            ],
            "directories": list(state.directories),
        }
    )


def _bytes_sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def _file_sha256(path: Path) -> str:
    return _bytes_sha256(path.read_bytes())
