from pathlib import Path

from nacl.public import PrivateKey
from nacl.signing import SigningKey

from spatial_swarm.attacks.valid_signature_agent import VerifierSnapshotForgeryAgent
from spatial_swarm.core.errors import FailureReason
from spatial_swarm.core.gateway import Gateway
from spatial_swarm.core.setup import EphemeralSetup
from spatial_swarm.experiments.report import RunLogger


def test_birth_setup_deletes_full_puzzle_seed_and_cut_fragments():
    setup = EphemeralSetup(agent_count=4, fragment_size=8, seed=41, p=257, timeout_ms=50.0)

    artifacts = setup.run()

    assert setup.full_puzzle is None
    assert setup.fragments is None
    assert setup.seed_material is None
    assert setup.shutdown_complete
    assert artifacts.report.full_puzzle_deleted
    assert artifacts.report.seed_deleted
    assert artifacts.report.setup_shutdown
    assert not hasattr(artifacts, "full_puzzle")
    assert not hasattr(artifacts, "seed")


def test_verifier_visible_state_after_setup_has_only_public_fingerprints():
    gateway = Gateway.create_swarm(agent_count=4, fragment_size=8, seed=42)
    snapshot = gateway.verifier_public_snapshot_after_setup()

    assert gateway.active_verifier is None
    assert gateway.setup_report is not None
    assert gateway.setup_report.full_puzzle_deleted
    assert gateway.setup_report.seed_deleted
    assert gateway.setup_report.setup_shutdown
    assert not hasattr(gateway, "seed")
    assert not hasattr(gateway.registry, "full_puzzle")
    assert not hasattr(gateway.registry, "seed")

    for registration in gateway.registry.all_registrations():
        assert not hasattr(registration, "fragment")
        assert not hasattr(registration, "coords")
        assert not isinstance(registration.verify_key, SigningKey)
        assert not isinstance(registration.verify_key, PrivateKey)

    for record in snapshot.agents:
        assert record.agent_id
        assert record.fragment_commitment
        assert record.fragment_size == 8
        assert not hasattr(record, "fragment")
        assert not hasattr(record, "coords")
        assert not hasattr(record, "private_key")
        assert not hasattr(record, "signing_key")
        assert not isinstance(record.verify_key, SigningKey)
        assert not isinstance(record.verify_key, PrivateKey)


def test_temporary_verifier_exits_after_checking_message():
    gateway = Gateway.create_swarm(agent_count=4, fragment_size=8, seed=43)

    result = gateway.send("agent_001", "agent_002", {"body": "temporary verifier"})

    assert result.passed
    assert gateway.active_verifier is None
    assert gateway.last_verifier_shutdown


def test_run_logs_do_not_contain_raw_setup_or_piece_material(tmp_path: Path):
    logger = RunLogger(tmp_path / "run")
    gateway = Gateway.create_swarm(agent_count=4, fragment_size=8, seed=44, logger=logger)

    result = gateway.send("agent_001", "agent_002", {"body": "redacted setup"})

    assert result.passed
    logs = (tmp_path / "run" / "events.jsonl").read_text(encoding="utf-8")
    forbidden = [
        "\"coords\"",
        "full_puzzle",
        "private_key",
        "signing_key",
        "plaintext",
        "decrypted",
        "\"seed\"",
        "seed:",
    ]
    for marker in forbidden:
        assert marker not in logs


def test_stolen_verifier_snapshot_cannot_forge_agent_piece():
    gateway = Gateway.create_swarm(agent_count=4, fragment_size=8, seed=45)
    snapshot = gateway.verifier_public_snapshot_after_setup()
    attack = VerifierSnapshotForgeryAgent("agent_004", seed=46)

    result = gateway.send(
        "agent_001",
        "agent_002",
        {"body": "snapshot forgery"},
        packet_provider=attack.replace_agent_packets,
    )

    assert snapshot.require("agent_004").fragment_commitment
    assert not result.passed
    assert result.failure_reason == FailureReason.WRONG_GEOMETRY.value
