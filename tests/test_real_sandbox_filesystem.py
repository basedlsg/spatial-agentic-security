"""Filesystem tracing and escape tests for Real Sandbox Gate v3."""

from __future__ import annotations

from pathlib import Path

from spatial_swarm.spatial_puzzle.experiments import real_sandbox_gate_v3 as V3
from spatial_swarm.spatial_puzzle.sandbox.filesystem_snapshot import diff, snapshot


def test_filesystem_snapshot_records_create_modify_delete_and_symlink(tmp_path: Path):
    root = tmp_path / "repo"
    root.mkdir()
    tracked = root / "tracked.txt"
    tracked.write_text("one\n", encoding="utf-8")
    removed = root / "removed.txt"
    removed.write_text("remove\n", encoding="utf-8")
    before = snapshot(root)
    tracked.write_text("two\n", encoding="utf-8")
    removed.unlink()
    (root / "created.txt").write_text("new\n", encoding="utf-8")
    (root / "link").symlink_to(tracked)
    delta = diff(before, snapshot(root))
    assert delta.modified == ("tracked.txt",)
    assert delta.deleted == ("removed.txt",)
    assert "created.txt" in delta.created
    assert "link" in delta.created


def test_full_gate_blocks_path_traversal_but_no_path_canonicalization_releases():
    full = V3.run_attack_case("path_traversal_outside", 0, V3.GuardConfig(min_block_ms=0))
    assert full.blocked is True
    assert full.released is False
    ablated = V3.run_ablation_case("no_path_canonicalization", 0, V3.GuardConfig(min_block_ms=0))
    assert ablated.released is True
    assert ablated.path_escape_released is True


def test_full_gate_blocks_symlink_escape_but_no_symlink_check_releases():
    full = V3.run_attack_case("symlink_escape", 0, V3.GuardConfig(min_block_ms=0))
    assert full.blocked is True
    assert "policy:symlink_escape" in full.internal_reasons
    ablated = V3.run_ablation_case("no_symlink_check", 0, V3.GuardConfig(min_block_ms=0))
    assert ablated.released is True
    assert ablated.path_escape_released is True
