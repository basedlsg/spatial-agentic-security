"""ActionEnvelope canonicalization boundary tests."""

from __future__ import annotations

import tempfile
from pathlib import Path

from spatial_swarm.spatial_puzzle.experiments import realistic_coding_gate_v2 as V2


def test_canonicalization_attacks_do_not_execute():
    cfg = V2.V2Config(min_block_ms=0.0)
    for scenario in V2.CANONICALIZATION_ATTACKS:
        row = V2.run_canonicalization_attack(scenario, 0, cfg)
        if scenario == "unicode_normalized_equivalent":
            assert row.executed is True
        else:
            assert row.executed is False, scenario
            assert row.blocked is True, scenario


def test_equivalent_unicode_normalization_converges():
    cfg = V2.V2Config(min_block_ms=0.0)
    with tempfile.TemporaryDirectory() as tmp:
        repo = V2._mk_repo(Path(tmp))
        canon = V2.ActionCanonicalizer(repo, cfg)
        composed = canon.envelope(V2.RawAction("read_file", "src/café.py"))
        decomposed = canon.envelope(V2.RawAction("read_file", "src/cafe\u0301.py"))
    assert composed.valid is True
    assert decomposed.valid is True
    assert composed.canonical_path == decomposed.canonical_path
    assert composed.action_hash == decomposed.action_hash


def test_similar_but_different_actions_hash_differently():
    cfg = V2.V2Config(min_block_ms=0.0)
    with tempfile.TemporaryDirectory() as tmp:
        repo = V2._mk_repo(Path(tmp))
        canon = V2.ActionCanonicalizer(repo, cfg)
        read_readme = canon.envelope(V2.RawAction("read_file", "README.md"))
        read_app = canon.envelope(V2.RawAction("read_file", "src/app.py"))
    assert read_readme.valid is True
    assert read_app.valid is True
    assert read_readme.action_hash != read_app.action_hash
