"""Systematic secret-redaction scanning for run artifacts.

v0.4 and v0.5 checked artifacts with ad-hoc ``rg`` greps. v0.6 turns that into a
reusable scanner with an explicit marker set so the check can run as an
automated test over an entire run directory (config, metrics, events, summaries,
environment, and any sidecar/container logs).

Markers are chosen to flag genuine raw secrets without tripping on legitimate
metric field names. Field-like markers are matched in their JSON-quoted form
(for example ``"coords"``) so that names such as ``decryptions_performed`` or
``geometry_checks_performed`` do not produce false positives.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

# Each entry is a literal substring searched for verbatim.
SECRET_MARKERS: tuple[str, ...] = (
    '"coords"',          # raw / transformed coordinates
    "private_key",       # private decryption keys
    "signing_key",       # private signing keys
    '"seed"',            # setup seed (object form)
    "seed:",             # setup seed (yaml-like form)
    "full_puzzle",       # the assembled puzzle
    "plaintext",         # decrypted proof payloads
    "decrypted",         # decrypted proof payloads
    "show_fragment",     # sidecar debug accessor
    "show_private_key",  # sidecar debug accessor
    "show_seed",         # sidecar debug accessor
)

# Files that are not expected to be UTF-8 text are skipped rather than decoded.
_BINARY_SUFFIXES = {".png", ".jpg", ".jpeg", ".gz", ".zip", ".pyc", ".so"}

# The redaction report legitimately names every marker, so scanning it would
# always "find" them. It is excluded from scans by filename.
_SKIP_NAMES = {"redaction.json"}


@dataclass(frozen=True)
class RedactionHit:
    path: str
    marker: str


def scan_text(text: str, markers: tuple[str, ...] = SECRET_MARKERS) -> list[str]:
    """Return the markers that appear in ``text``."""

    return [marker for marker in markers if marker in text]


def scan_run_dir(
    run_dir: Path,
    markers: tuple[str, ...] = SECRET_MARKERS,
) -> list[RedactionHit]:
    """Scan every text file under ``run_dir`` for secret markers."""

    hits: list[RedactionHit] = []
    for path in sorted(run_dir.rglob("*")):
        if not path.is_file() or path.suffix in _BINARY_SUFFIXES:
            continue
        if path.name in _SKIP_NAMES:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        rel = str(path.relative_to(run_dir))
        for marker in scan_text(text, markers):
            hits.append(RedactionHit(path=rel, marker=marker))
    return hits


def redaction_report(run_dir: Path) -> dict[str, object]:
    """Summarise a redaction scan for inclusion in metrics."""

    hits = scan_run_dir(run_dir)
    return {
        "markers_checked": list(SECRET_MARKERS),
        "secret_markers_found": len(hits),
        "hits": [{"path": hit.path, "marker": hit.marker} for hit in hits],
        "clean": not hits,
    }
