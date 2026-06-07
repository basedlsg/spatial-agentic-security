"""Run logging and report helpers."""

from __future__ import annotations

import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional


FORBIDDEN_LOG_KEYS = {
    "fragment",
    "fragments",
    "coords",
    "private_key",
    "signing_key",
    "plaintext",
    "decrypted",
}


def utc_run_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%S.%fZ")


class RunLogger:
    def __init__(self, run_dir: Path, run_id: Optional[str] = None):
        self.run_dir = run_dir
        self.run_id = run_id or run_dir.name
        self.run_dir.mkdir(parents=True, exist_ok=True)
        self.events_path = self.run_dir / "events.jsonl"

    def emit(self, event: dict[str, Any]) -> None:
        forbidden = FORBIDDEN_LOG_KEYS.intersection(event)
        if forbidden:
            raise ValueError(f"refusing to log sensitive fields: {sorted(forbidden)}")
        event.setdefault("run_id", self.run_id)
        with self.events_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")

    def emit_many(self, events: Iterable[dict[str, Any]]) -> None:
        for event in events:
            self.emit(event)


def write_environment(run_dir: Path) -> None:
    payload = {
        "python": platform.python_version(),
        "platform": platform.platform(),
        "cwd": os.getcwd(),
    }
    (run_dir / "environment.txt").write_text(
        "\n".join(f"{key}: {value}" for key, value in payload.items()) + "\n",
        encoding="utf-8",
    )


def write_git_commit(run_dir: Path) -> None:
    try:
        commit = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    except Exception:
        commit = "unknown"
    (run_dir / "git_commit.txt").write_text(commit + "\n", encoding="utf-8")


def write_yaml_like(path: Path, values: dict[str, Any]) -> None:
    lines = []
    for key, value in values.items():
        if isinstance(value, str):
            lines.append(f"{key}: {value}")
        else:
            lines.append(f"{key}: {json.dumps(value)}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
