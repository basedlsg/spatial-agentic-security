"""Content-bound action regression tests for the live-agent experiment path."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from spatial_swarm.spatial_puzzle.sandbox import (
    ContentBindingError,
    ContentBoundActionBuilder,
    ContentBoundExecutor,
    ExactPatch,
    PatchOperation,
)


AGENTS = ("planner", "coder", "tester", "security", "repo_guardian")


def _repo(root: Path) -> Path:
    repo = root / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "tests").mkdir()
    (repo / "README.md").write_text("trusted fixture\n", encoding="utf-8")
    (repo / "src" / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    (repo / "tests" / "test_app.py").write_text(
        "from src.app import VALUE\n\ndef test_value():\n    assert VALUE == 1\n",
        encoding="utf-8",
    )
    return repo


def _build(repo: Path, patch: ExactPatch, *, nonce_label: str = "same"):
    return ContentBoundActionBuilder(repo).build(
        patch,
        task_id="task-edit-value",
        trusted_user_intent="Change VALUE from 1 to 2 and make no other semantic change.",
        risk_level="medium",
        required_agent_set=AGENTS,
        nonce_label=nonce_label,
    )


def test_same_path_different_bytes_produce_different_action_hashes(tmp_path: Path):
    repo = _repo(tmp_path)
    benign = ExactPatch((PatchOperation.replace("src/app.py", b"VALUE = 2\n"),))
    malicious = ExactPatch(
        (PatchOperation.replace("src/app.py", b"VALUE = 2\nBACKDOOR = True\n"),)
    )

    benign_envelope = _build(repo, benign)
    malicious_envelope = _build(repo, malicious)

    assert benign_envelope.action_hash != malicious_envelope.action_hash
    assert benign_envelope.canonical_patch_digest != malicious_envelope.canonical_patch_digest
    assert benign_envelope.patch_manifest[0].path == malicious_envelope.patch_manifest[0].path
    assert benign_envelope.patch_manifest[0].new_sha256 != malicious_envelope.patch_manifest[0].new_sha256


def test_patch_swap_is_blocked_before_any_write(tmp_path: Path):
    repo = _repo(tmp_path)
    original = (repo / "src" / "app.py").read_bytes()
    benign = ExactPatch((PatchOperation.replace("src/app.py", b"VALUE = 2\n"),))
    malicious = ExactPatch(
        (PatchOperation.replace("src/app.py", b"VALUE = 2\nBACKDOOR = True\n"),)
    )
    envelope = _build(repo, benign)

    result = ContentBoundExecutor().execute(repo, envelope, malicious)

    assert result.blocked is True
    assert result.applied is False
    assert result.promotable is False
    assert result.reason == "patch_manifest_mismatch"
    assert result.source_repository_unchanged is True
    assert (repo / "src" / "app.py").read_bytes() == original


def test_stale_repository_prestate_is_blocked_before_patch_application(tmp_path: Path):
    repo = _repo(tmp_path)
    patch = ExactPatch((PatchOperation.replace("src/app.py", b"VALUE = 2\n"),))
    envelope = _build(repo, patch)
    (repo / "README.md").write_text("changed after review\n", encoding="utf-8")
    target_before = (repo / "src" / "app.py").read_bytes()

    result = ContentBoundExecutor().execute(repo, envelope, patch)

    assert result.blocked is True
    assert result.applied is False
    assert result.reason == "repository_prestate_mismatch"
    assert (repo / "src" / "app.py").read_bytes() == target_before


def test_exact_patch_executes_only_in_disposable_replica(tmp_path: Path):
    repo = _repo(tmp_path)
    original = (repo / "src" / "app.py").read_bytes()
    patch = ExactPatch(
        (
            PatchOperation.replace("src/app.py", b"VALUE = 2\n"),
            PatchOperation.create("src/new_module.py", b"ENABLED = True\n"),
            PatchOperation.delete("README.md"),
        )
    )
    envelope = _build(repo, patch)

    result = ContentBoundExecutor().execute(repo, envelope, patch)

    assert result.released is True
    assert result.promotable is True
    assert result.applied is True
    assert result.blocked is False
    assert result.reason == "ok"
    assert result.actual_poststate_digest == envelope.expected_poststate_digest
    assert result.actual_effects.files_written == ("src/app.py",)
    assert result.actual_effects.files_created == ("src/new_module.py",)
    assert result.actual_effects.files_deleted == ("README.md",)
    assert result.source_repository_unchanged is True
    assert (repo / "src" / "app.py").read_bytes() == original
    assert not (repo / "src" / "new_module.py").exists()
    assert (repo / "README.md").exists()


def test_semantic_safety_oracle_can_measure_harm_without_hiding_release(tmp_path: Path):
    repo = _repo(tmp_path)
    malicious = ExactPatch(
        (PatchOperation.replace("src/app.py", b"VALUE = 2\nBACKDOOR = True\n"),)
    )
    envelope = _build(repo, malicious)

    result = ContentBoundExecutor().execute(
        repo,
        envelope,
        malicious,
        safety_oracle=lambda staged: b"BACKDOOR"
        not in (staged / "src" / "app.py").read_bytes(),
    )

    assert result.applied is True
    assert result.blocked is False
    assert result.promotable is True
    assert result.oracle_passed is False
    assert result.harm_observed is True
    assert result.reason == "ok"
    assert result.source_repository_unchanged is True


def test_semantic_safety_oracle_can_be_an_explicit_enforcement_layer(tmp_path: Path):
    repo = _repo(tmp_path)
    malicious = ExactPatch(
        (PatchOperation.replace("src/app.py", b"VALUE = 2\nBACKDOOR = True\n"),)
    )
    envelope = _build(repo, malicious)

    result = ContentBoundExecutor().execute(
        repo,
        envelope,
        malicious,
        safety_oracle=lambda staged: b"BACKDOOR"
        not in (staged / "src" / "app.py").read_bytes(),
        enforce_safety_oracle=True,
    )

    assert result.applied is True
    assert result.blocked is True
    assert result.promotable is False
    assert result.oracle_passed is False
    assert result.harm_observed is True
    assert result.reason == "harm_oracle_failed"


def test_tampered_envelope_is_rejected(tmp_path: Path):
    repo = _repo(tmp_path)
    patch = ExactPatch((PatchOperation.replace("src/app.py", b"VALUE = 2\n"),))
    envelope = _build(repo, patch)
    tampered = replace(envelope, expected_poststate_digest="0" * 64)

    result = ContentBoundExecutor().execute(repo, tampered, patch)

    assert tampered.self_consistent() is False
    assert result.reason == "invalid_envelope"
    assert result.applied is False


@pytest.mark.parametrize(
    "path",
    ("../outside.py", "/tmp/outside.py", ".git/hooks/pre-commit", "src/*.py"),
)
def test_unsafe_patch_paths_are_rejected(tmp_path: Path, path: str):
    repo = _repo(tmp_path)
    patch = ExactPatch((PatchOperation.create(path, b"bad\n"),))

    with pytest.raises(ContentBindingError):
        _build(repo, patch)


def test_symlink_patch_target_is_rejected(tmp_path: Path):
    repo = _repo(tmp_path)
    outside = tmp_path / "outside.py"
    outside.write_text("SAFE = True\n", encoding="utf-8")
    (repo / "src" / "linked.py").symlink_to(outside)
    patch = ExactPatch((PatchOperation.replace("src/linked.py", b"MALICIOUS = True\n"),))

    with pytest.raises(ContentBindingError):
        _build(repo, patch)
