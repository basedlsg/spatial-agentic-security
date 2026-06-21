"""Effect record construction from filesystem and wrapper observations."""

from __future__ import annotations

from .filesystem_snapshot import FilesystemDelta
from .results import EffectRecord


def effect_from_delta(delta: FilesystemDelta) -> EffectRecord:
    return EffectRecord(
        files_written=tuple(sorted(set(delta.modified).union(delta.symlink_changes))),
        files_created=delta.created,
        files_deleted=delta.deleted,
    )
