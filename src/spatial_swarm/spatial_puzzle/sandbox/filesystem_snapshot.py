"""Filesystem snapshot diffing for sandbox workspaces."""

from __future__ import annotations

import hashlib
import os
import stat
from dataclasses import dataclass
from pathlib import Path


IGNORED_PARTS = {".git", "__pycache__"}
IGNORED_SUFFIXES = {".pyc", ".pyo"}


@dataclass(frozen=True)
class FileState:
    kind: str
    digest: str
    mode: int
    target: str = ""


@dataclass(frozen=True)
class FilesystemSnapshot:
    files: dict[str, FileState]
    directories: tuple[str, ...]


@dataclass(frozen=True)
class FilesystemDelta:
    created: tuple[str, ...]
    modified: tuple[str, ...]
    deleted: tuple[str, ...]
    symlink_changes: tuple[str, ...]


def snapshot(root: Path) -> FilesystemSnapshot:
    root = root.resolve()
    files: dict[str, FileState] = {}
    directories: list[str] = []
    for current, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [name for name in dirnames if name not in IGNORED_PARTS]
        current_path = Path(current)
        rel_dir = current_path.relative_to(root).as_posix()
        if rel_dir != ".":
            directories.append(rel_dir)
        for filename in filenames:
            path = current_path / filename
            rel = path.relative_to(root).as_posix()
            if _ignored(Path(rel)):
                continue
            st = path.lstat()
            if stat.S_ISLNK(st.st_mode):
                files[rel] = FileState("symlink", "", stat.S_IMODE(st.st_mode), os.readlink(path))
            elif stat.S_ISREG(st.st_mode):
                files[rel] = FileState("file", _hash_file(path), stat.S_IMODE(st.st_mode))
            else:
                files[rel] = FileState("other", "", stat.S_IMODE(st.st_mode))
    return FilesystemSnapshot(files=files, directories=tuple(sorted(directories)))


def diff(before: FilesystemSnapshot, after: FilesystemSnapshot) -> FilesystemDelta:
    before_keys = set(before.files)
    after_keys = set(after.files)
    created = after_keys - before_keys
    deleted = before_keys - after_keys
    common = before_keys.intersection(after_keys)
    modified = {
        path
        for path in common
        if before.files[path].kind == "file"
        and after.files[path].kind == "file"
        and (
            before.files[path].digest != after.files[path].digest
            or before.files[path].mode != after.files[path].mode
        )
    }
    symlink_changes = {
        path
        for path in common
        if (
            before.files[path].kind == "symlink"
            or after.files[path].kind == "symlink"
        )
        and before.files[path] != after.files[path]
    }
    return FilesystemDelta(
        created=tuple(sorted(created)),
        modified=tuple(sorted(modified)),
        deleted=tuple(sorted(deleted)),
        symlink_changes=tuple(sorted(symlink_changes)),
    )


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ignored(path: Path) -> bool:
    return any(part in IGNORED_PARTS for part in path.parts) or path.suffix in IGNORED_SUFFIXES
