"""v0.6 systematic secret-redaction scanning over run artifacts."""

from __future__ import annotations

from pathlib import Path

from spatial_swarm.experiments.redaction import (
    SECRET_MARKERS,
    redaction_report,
    scan_run_dir,
    scan_text,
)
from spatial_swarm.experiments.runner import run_experiment


def test_clean_forgery_run_has_no_secret_markers(tmp_path: Path):
    run_dir = run_experiment(
        scenario="ai_forgery_matrix",
        agent_count=4,
        fragment_size=8,
        attempts=2,
        seed=51,
        output_root=tmp_path,
    )
    hits = scan_run_dir(run_dir)
    assert hits == [], f"unexpected secret markers: {hits}"
    report = redaction_report(run_dir)
    assert report["clean"] is True
    assert report["secret_markers_found"] == 0


def test_snapshot_forgery_run_is_clean(tmp_path: Path):
    run_dir = run_experiment(
        scenario="snapshot_forgery_matrix",
        agent_count=4,
        fragment_size=8,
        attempts=2,
        seed=52,
        output_root=tmp_path,
    )
    assert scan_run_dir(run_dir) == []


def test_scanner_detects_planted_secret(tmp_path: Path):
    """Positive control for the scanner itself: it must flag a real leak."""

    (tmp_path / "leak.txt").write_text(
        'oops {"coords": [[1,2,3]], "signing_key": "deadbeef"}\n',
        encoding="utf-8",
    )
    hits = scan_run_dir(tmp_path)
    markers = {hit.marker for hit in hits}
    assert '"coords"' in markers
    assert "signing_key" in markers


def test_scan_text_matches_each_marker():
    # Some markers are substrings of others (e.g. "private_key" in
    # "show_private_key"); the scanner reports every match, so assert membership.
    for marker in SECRET_MARKERS:
        assert marker in scan_text(f"prefix {marker} suffix")


def test_redaction_report_is_not_self_incriminating(tmp_path: Path):
    """redaction.json names every marker, so it must be excluded from scans."""

    run_dir = run_experiment(
        scenario="ai_forgery_matrix",
        agent_count=4,
        fragment_size=8,
        attempts=1,
        seed=53,
        output_root=tmp_path,
    )
    assert (run_dir / "redaction.json").exists()
    assert scan_run_dir(run_dir) == []
