"""Canonical hashing utilities."""

from __future__ import annotations

import hashlib
import json
from typing import Any


def canonical_json(value: Any) -> str:
    """Return a deterministic compact JSON representation."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def sha256_hex(value: Any) -> str:
    """Hash structured data or bytes with SHA-256."""

    if isinstance(value, bytes):
        payload = value
    elif isinstance(value, str):
        payload = value.encode("utf-8")
    else:
        payload = canonical_json(value).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def hash_bytes(label: str, *parts: Any) -> bytes:
    """Domain-separated SHA-256 bytes."""

    return hashlib.sha256(canonical_json({"label": label, "parts": parts}).encode("utf-8")).digest()
