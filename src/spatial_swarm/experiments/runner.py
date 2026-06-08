"""Command-line experiment runner for USAG."""

from __future__ import annotations

import argparse
import json
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator, Optional

from spatial_swarm.attacks.duplicate_agent import DuplicateAgent
from spatial_swarm.attacks.fake_agent import RandomFakeAgent
from spatial_swarm.attacks.fuzzer import PacketFuzzer
from spatial_swarm.attacks.malformed_agent import MalformedAgent
from spatial_swarm.attacks.overbudget_agent import OverBudgetAgent, UnderBudgetAgent
from spatial_swarm.attacks.slow_agent import SlowAgent
from spatial_swarm.attacks.stolen_piece_agent import PartialSwarmAgent, StolenSinglePieceAgent
from spatial_swarm.attacks.valid_signature_agent import (
    CorrectGeometryWrongAgentIdAgent,
    StolenFragmentOnlyAgent,
    StolenSigningKeyOnlyAgent,
    ValidSignatureWrongGeometryAgent,
    ValidSignatureWrongMessageHashAgent,
    ValidSignatureWrongTransformAgent,
)
from spatial_swarm.attacks.wrong_message_agent import WrongMessageAgent
from spatial_swarm.core.gateway import Gateway
from spatial_swarm.experiments.baselines import (
    BASELINE_MODES,
    BaselineResult,
    evaluate_baseline_mode,
    summarize_baseline_results,
)
from spatial_swarm.crypto.hashing import sha256_hex
from spatial_swarm.experiments.metrics import (
    process_resource_use,
    summarize_results,
    write_metrics,
    write_summary,
)
from spatial_swarm.experiments.report import (
    RunLogger,
    utc_run_id,
    write_environment,
    write_git_commit,
    write_yaml_like,
)
from spatial_swarm.protocol.verifier import VerificationResult, VerifierOptions


Scenario = Callable[[int, int, int, Optional[RunLogger]], VerificationResult]

_ACTIVE_VERIFIER_OPTIONS: Optional[VerifierOptions] = None


def _target_agent_id(agent_count: int, position: str) -> str:
    if agent_count <= 1:
        index = 1
    elif position == "early":
        index = 1
    elif position == "middle":
        index = max(1, agent_count // 2)
    elif position == "late":
        index = agent_count
    else:
        raise ValueError(f"unknown packet position {position!r}")
    return f"agent_{index:03d}"


def _source_agent_id(agent_count: int, target_agent_id: str) -> str:
    for index in range(1, agent_count + 1):
        candidate = f"agent_{index:03d}"
        if candidate != target_agent_id:
            return candidate
    return target_agent_id


def _gateway(agent_count: int, fragment_size: int, seed: int, logger: Optional[RunLogger]) -> Gateway:
    return Gateway.create_swarm(
        agent_count=agent_count,
        fragment_size=fragment_size,
        seed=seed,
        logger=logger,
        verifier_options=_ACTIVE_VERIFIER_OPTIONS,
    )


@contextmanager
def _verifier_options(options: Optional[VerifierOptions]) -> Iterator[None]:
    global _ACTIVE_VERIFIER_OPTIONS
    previous = _ACTIVE_VERIFIER_OPTIONS
    _ACTIVE_VERIFIER_OPTIONS = options
    try:
        yield
    finally:
        _ACTIVE_VERIFIER_OPTIONS = previous


def run_honest(agent_count: int, fragment_size: int, seed: int, logger: Optional[RunLogger]) -> VerificationResult:
    gateway = _gateway(agent_count, fragment_size, seed, logger)
    return gateway.send("agent_001", "agent_002", {"type": "demo", "body": "honest"})


def run_missing(agent_count: int, fragment_size: int, seed: int, logger: Optional[RunLogger]) -> VerificationResult:
    gateway = _gateway(agent_count, fragment_size, seed, logger)

    def provider(gateway: Gateway, message, challenge):
        return gateway.collect_honest_packets(message, challenge)[:-1]

    return gateway.send("agent_001", "agent_002", {"type": "demo", "body": "missing"}, packet_provider=provider)


def run_fake_agent(agent_count: int, fragment_size: int, seed: int, logger: Optional[RunLogger]) -> VerificationResult:
    return run_fake_agent_middle(agent_count, fragment_size, seed, logger)


def _run_fake_agent_position(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
    position: str,
) -> VerificationResult:
    gateway = _gateway(agent_count, fragment_size, seed, logger)
    target_agent_id = _target_agent_id(agent_count, position)
    fake = RandomFakeAgent(target_agent_id, seed=seed + 42)
    return gateway.send(
        "agent_001",
        "agent_002",
        {"type": "demo", "body": f"fake replacement {position}"},
        packet_provider=fake.replace_agent_packets,
    )


def run_fake_agent_early(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
) -> VerificationResult:
    return _run_fake_agent_position(agent_count, fragment_size, seed, logger, "early")


def run_fake_agent_middle(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
) -> VerificationResult:
    return _run_fake_agent_position(agent_count, fragment_size, seed, logger, "middle")


def run_fake_agent_late(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
) -> VerificationResult:
    return _run_fake_agent_position(agent_count, fragment_size, seed, logger, "late")


def run_unregistered_fake_agent(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
) -> VerificationResult:
    gateway = _gateway(agent_count, fragment_size, seed, logger)
    fake = RandomFakeAgent("agent_999", seed=seed + 42)
    return gateway.send(
        "agent_001",
        "agent_002",
        {"type": "demo", "body": "unregistered fake"},
        packet_provider=lambda gateway, message, challenge: [fake.packet(gateway, message, challenge)],
    )


def run_valid_signature_wrong_geometry(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
) -> VerificationResult:
    return run_valid_signature_wrong_geometry_middle(agent_count, fragment_size, seed, logger)


def _run_valid_signature_wrong_geometry_position(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
    position: str,
) -> VerificationResult:
    gateway = _gateway(agent_count, fragment_size, seed, logger)
    target_agent_id = _target_agent_id(agent_count, position)
    attack = ValidSignatureWrongGeometryAgent(
        target_agent_id,
        _source_agent_id(agent_count, target_agent_id),
    )
    return gateway.send(
        "agent_001",
        "agent_002",
        {"type": "demo", "body": f"valid signature wrong geometry {position}"},
        packet_provider=attack.replace_agent_packets,
    )


def run_valid_signature_wrong_geometry_early(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
) -> VerificationResult:
    return _run_valid_signature_wrong_geometry_position(agent_count, fragment_size, seed, logger, "early")


def run_valid_signature_wrong_geometry_middle(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
) -> VerificationResult:
    return _run_valid_signature_wrong_geometry_position(agent_count, fragment_size, seed, logger, "middle")


def run_valid_signature_wrong_geometry_late(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
) -> VerificationResult:
    return _run_valid_signature_wrong_geometry_position(agent_count, fragment_size, seed, logger, "late")


def run_valid_signature_wrong_transform(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
) -> VerificationResult:
    return run_valid_signature_wrong_transform_middle(agent_count, fragment_size, seed, logger)


def _run_valid_signature_wrong_transform_position(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
    position: str,
) -> VerificationResult:
    gateway = _gateway(agent_count, fragment_size, seed, logger)
    target_agent_id = _target_agent_id(agent_count, position)
    attack = ValidSignatureWrongTransformAgent(
        target_agent_id,
        _source_agent_id(agent_count, target_agent_id),
    )
    return gateway.send(
        "agent_001",
        "agent_002",
        {"type": "demo", "body": f"valid signature wrong transform {position}"},
        packet_provider=attack.replace_agent_packets,
    )


def run_valid_signature_wrong_transform_early(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
) -> VerificationResult:
    return _run_valid_signature_wrong_transform_position(agent_count, fragment_size, seed, logger, "early")


def run_valid_signature_wrong_transform_middle(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
) -> VerificationResult:
    return _run_valid_signature_wrong_transform_position(agent_count, fragment_size, seed, logger, "middle")


def run_valid_signature_wrong_transform_late(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
) -> VerificationResult:
    return _run_valid_signature_wrong_transform_position(agent_count, fragment_size, seed, logger, "late")


def run_valid_signature_wrong_message_hash(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
) -> VerificationResult:
    return run_valid_signature_wrong_message_hash_middle(agent_count, fragment_size, seed, logger)


def _run_valid_signature_wrong_message_hash_position(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
    position: str,
) -> VerificationResult:
    gateway = _gateway(agent_count, fragment_size, seed, logger)
    target_agent_id = _target_agent_id(agent_count, position)
    attack = ValidSignatureWrongMessageHashAgent(
        target_agent_id,
        _source_agent_id(agent_count, target_agent_id),
    )
    return gateway.send(
        "agent_001",
        "agent_002",
        {"type": "demo", "body": f"valid signature wrong message hash {position}"},
        packet_provider=attack.replace_agent_packets,
    )


def run_valid_signature_wrong_message_hash_early(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
) -> VerificationResult:
    return _run_valid_signature_wrong_message_hash_position(agent_count, fragment_size, seed, logger, "early")


def run_valid_signature_wrong_message_hash_middle(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
) -> VerificationResult:
    return _run_valid_signature_wrong_message_hash_position(agent_count, fragment_size, seed, logger, "middle")


def run_valid_signature_wrong_message_hash_late(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
) -> VerificationResult:
    return _run_valid_signature_wrong_message_hash_position(agent_count, fragment_size, seed, logger, "late")


def run_stolen_signing_key_only(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
) -> VerificationResult:
    gateway = _gateway(agent_count, fragment_size, seed, logger)
    target_agent_id = _target_agent_id(agent_count, "middle")
    attack = StolenSigningKeyOnlyAgent(target_agent_id, _source_agent_id(agent_count, target_agent_id))
    return gateway.send(
        "agent_001",
        "agent_002",
        {"type": "demo", "body": "stolen signing key only"},
        packet_provider=attack.replace_agent_packets,
    )


def run_stolen_signing_authority_only(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
) -> VerificationResult:
    return run_stolen_signing_key_only(agent_count, fragment_size, seed, logger)


def run_stolen_fragment_only(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
) -> VerificationResult:
    gateway = _gateway(agent_count, fragment_size, seed, logger)
    attack = StolenFragmentOnlyAgent(_target_agent_id(agent_count, "middle"), seed=seed + 77)
    return gateway.send(
        "agent_001",
        "agent_002",
        {"type": "demo", "body": "stolen fragment only"},
        packet_provider=attack.replace_agent_packets,
    )


def run_correct_geometry_wrong_agent_id(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
) -> VerificationResult:
    gateway = _gateway(agent_count, fragment_size, seed, logger)
    target_agent_id = _target_agent_id(agent_count, "middle")
    attack = CorrectGeometryWrongAgentIdAgent(
        target_agent_id,
        _source_agent_id(agent_count, target_agent_id),
    )
    return gateway.send(
        "agent_001",
        "agent_002",
        {"type": "demo", "body": "correct geometry wrong agent id"},
        packet_provider=attack.replace_agent_packets,
    )


def run_replay(agent_count: int, fragment_size: int, seed: int, logger: Optional[RunLogger]) -> VerificationResult:
    return run_replay_early(agent_count, fragment_size, seed, logger)


def _run_replay_position(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
    position: str,
) -> VerificationResult:
    gateway = _gateway(agent_count, fragment_size, seed, logger)
    old_message = gateway.freeze("agent_001", "agent_002", {"body": "old"}, nonce="old")
    old_challenge = gateway.challenge(old_message)
    old_packets = gateway.collect_honest_packets(old_message, old_challenge)
    old_by_agent = {packet.agent_id: packet for packet in old_packets}
    target_agent_id = _target_agent_id(agent_count, position)

    def provider(gateway: Gateway, message, challenge):
        current_packets = gateway.collect_honest_packets(message, challenge)
        return [
            old_by_agent[packet.agent_id] if packet.agent_id == target_agent_id else packet
            for packet in current_packets
        ]

    return gateway.send(
        "agent_001",
        "agent_002",
        {"body": f"new replay {position}"},
        nonce="new",
        packet_provider=provider,
    )


def run_replay_early(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
) -> VerificationResult:
    return _run_replay_position(agent_count, fragment_size, seed, logger, "early")


def run_replay_middle(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
) -> VerificationResult:
    return _run_replay_position(agent_count, fragment_size, seed, logger, "middle")


def run_replay_late(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
) -> VerificationResult:
    return _run_replay_position(agent_count, fragment_size, seed, logger, "late")


def run_wrong_message(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
) -> VerificationResult:
    gateway = _gateway(agent_count, fragment_size, seed, logger)
    other_message = gateway.freeze("agent_001", "agent_002", {"body": "other"}, nonce="other")
    other_challenge = gateway.challenge(other_message)
    wrong = WrongMessageAgent()
    return gateway.send(
        "agent_001",
        "agent_002",
        {"body": "current"},
        nonce="current",
        packet_provider=lambda g, _m, _c: wrong.packets_for_other_message(g, other_message, other_challenge),
    )


def run_duplicate(agent_count: int, fragment_size: int, seed: int, logger: Optional[RunLogger]) -> VerificationResult:
    gateway = _gateway(agent_count, fragment_size, seed, logger)
    duplicate = DuplicateAgent("agent_001")
    return gateway.send("agent_001", "agent_002", {"body": "duplicate"}, packet_provider=duplicate.packets)


def run_overbudget(agent_count: int, fragment_size: int, seed: int, logger: Optional[RunLogger]) -> VerificationResult:
    gateway = _gateway(agent_count, fragment_size, seed, logger)
    overbudget = OverBudgetAgent("agent_001")
    return gateway.send("agent_001", "agent_002", {"body": "overbudget"}, packet_provider=overbudget.replace_agent_packets)


def run_underbudget(agent_count: int, fragment_size: int, seed: int, logger: Optional[RunLogger]) -> VerificationResult:
    gateway = _gateway(agent_count, fragment_size, seed, logger)
    underbudget = UnderBudgetAgent("agent_001")
    return gateway.send(
        "agent_001",
        "agent_002",
        {"body": "underbudget"},
        packet_provider=underbudget.replace_agent_packets,
    )


def run_malformed(agent_count: int, fragment_size: int, seed: int, logger: Optional[RunLogger]) -> VerificationResult:
    gateway = _gateway(agent_count, fragment_size, seed, logger)
    malformed = MalformedAgent("agent_001")
    return gateway.send("agent_001", "agent_002", {"body": "malformed"}, packet_provider=malformed.packets)


def run_slow(agent_count: int, fragment_size: int, seed: int, logger: Optional[RunLogger]) -> VerificationResult:
    gateway = _gateway(agent_count, fragment_size, seed, logger)
    slow = SlowAgent("agent_001")
    return gateway.send("agent_001", "agent_002", {"body": "slow"}, packet_provider=slow.replace_agent_packets)


def run_stolen_piece(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
) -> VerificationResult:
    gateway = _gateway(agent_count, fragment_size, seed, logger)
    stolen = StolenSinglePieceAgent("agent_001")
    return gateway.send("agent_001", "agent_002", {"body": "stolen"}, packet_provider=stolen.packets)


def run_partial_swarm(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
) -> VerificationResult:
    gateway = _gateway(agent_count, fragment_size, seed, logger)
    partial = PartialSwarmAgent(max(1, agent_count - 1))
    return gateway.send("agent_001", "agent_002", {"body": "partial"}, packet_provider=partial.packets)


def run_all_but_one_valid_spatial_piece(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
) -> VerificationResult:
    return run_partial_swarm(agent_count, fragment_size, seed, logger)


def run_scale_smoke(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
) -> VerificationResult:
    gateway = _gateway(agent_count, fragment_size, seed, logger)
    fake_id = f"agent_{agent_count:03d}" if agent_count >= 1 else "agent_001"
    fake = RandomFakeAgent(fake_id, seed=seed + 99)
    return gateway.send(
        "agent_001",
        "agent_002",
        {"type": "scale_smoke", "agents": agent_count},
        packet_provider=fake.replace_agent_packets,
    )


def run_fuzz_malformed_packet(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
) -> VerificationResult:
    gateway = _gateway(agent_count, fragment_size, seed, logger)
    fuzzer = PacketFuzzer(seed, mode="single")
    return gateway.send(
        "agent_001",
        "agent_002",
        {"body": "fuzz malformed packet"},
        packet_provider=fuzzer.packets,
    )


def run_fuzz_mixed_packet_set(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
) -> VerificationResult:
    gateway = _gateway(agent_count, fragment_size, seed, logger)
    fuzzer = PacketFuzzer(seed, mode="mixed")
    return gateway.send(
        "agent_001",
        "agent_002",
        {"body": "fuzz mixed packet set"},
        packet_provider=fuzzer.packets,
    )


def run_fuzz_replay_mutation(
    agent_count: int,
    fragment_size: int,
    seed: int,
    logger: Optional[RunLogger],
) -> VerificationResult:
    gateway = _gateway(agent_count, fragment_size, seed, logger)
    fuzzer = PacketFuzzer(seed, mode="replay")
    return gateway.send(
        "agent_001",
        "agent_002",
        {"body": "fuzz replay mutation"},
        nonce="fuzz-current",
        packet_provider=fuzzer.packets,
    )


SCENARIOS: dict[str, Scenario] = {
    "honest": run_honest,
    "missing": run_missing,
    "fake_agent": run_fake_agent,
    "fake_agent_early": run_fake_agent_early,
    "fake_agent_middle": run_fake_agent_middle,
    "fake_agent_late": run_fake_agent_late,
    "unregistered_fake_agent": run_unregistered_fake_agent,
    "valid_signature_wrong_geometry": run_valid_signature_wrong_geometry,
    "valid_signature_wrong_geometry_early": run_valid_signature_wrong_geometry_early,
    "valid_signature_wrong_geometry_middle": run_valid_signature_wrong_geometry_middle,
    "valid_signature_wrong_geometry_late": run_valid_signature_wrong_geometry_late,
    "valid_signature_wrong_transform": run_valid_signature_wrong_transform,
    "valid_signature_wrong_transform_early": run_valid_signature_wrong_transform_early,
    "valid_signature_wrong_transform_middle": run_valid_signature_wrong_transform_middle,
    "valid_signature_wrong_transform_late": run_valid_signature_wrong_transform_late,
    "valid_signature_wrong_message_hash": run_valid_signature_wrong_message_hash,
    "valid_signature_wrong_message_hash_early": run_valid_signature_wrong_message_hash_early,
    "valid_signature_wrong_message_hash_middle": run_valid_signature_wrong_message_hash_middle,
    "valid_signature_wrong_message_hash_late": run_valid_signature_wrong_message_hash_late,
    "stolen_signing_key_only": run_stolen_signing_key_only,
    "stolen_signing_authority_only": run_stolen_signing_authority_only,
    "stolen_fragment_only": run_stolen_fragment_only,
    "correct_geometry_wrong_agent_id": run_correct_geometry_wrong_agent_id,
    "replay": run_replay,
    "replay_early": run_replay_early,
    "replay_middle": run_replay_middle,
    "replay_late": run_replay_late,
    "wrong_message": run_wrong_message,
    "duplicate": run_duplicate,
    "overbudget": run_overbudget,
    "underbudget": run_underbudget,
    "malformed": run_malformed,
    "slow": run_slow,
    "stolen_piece": run_stolen_piece,
    "partial_swarm": run_partial_swarm,
    "all_but_one_valid_spatial_piece": run_all_but_one_valid_spatial_piece,
    "scale_smoke": run_scale_smoke,
    "fuzz_malformed_packet": run_fuzz_malformed_packet,
    "fuzz_mixed_packet_set": run_fuzz_mixed_packet_set,
    "fuzz_replay_mutation": run_fuzz_replay_mutation,
}


SCENARIO_GROUPS: dict[str, list[str]] = {
    "v0_2_matrix": [
        "honest",
        "fake_agent",
        "unregistered_fake_agent",
        "replay",
        "wrong_message",
        "overbudget",
        "underbudget",
        "malformed",
        "duplicate",
        "slow",
        "missing",
        "partial_swarm",
        "stolen_piece",
        "stolen_signing_authority_only",
        "stolen_fragment_only",
        "correct_geometry_wrong_agent_id",
        "valid_signature_wrong_geometry_early",
        "valid_signature_wrong_geometry_middle",
        "valid_signature_wrong_geometry_late",
        "valid_signature_wrong_transform_early",
        "valid_signature_wrong_transform_middle",
        "valid_signature_wrong_transform_late",
        "valid_signature_wrong_message_hash_early",
        "valid_signature_wrong_message_hash_middle",
        "valid_signature_wrong_message_hash_late",
    ],
    "v0_2_focused_10000": [
        "honest",
        "fake_agent",
        "unregistered_fake_agent",
        "replay",
        "wrong_message",
        "valid_signature_wrong_geometry",
        "valid_signature_wrong_transform",
        "stolen_signing_authority_only",
        "stolen_fragment_only",
        "correct_geometry_wrong_agent_id",
    ],
    "v0_3_focused_10000": [
        "honest",
        "fake_agent",
        "unregistered_fake_agent",
        "replay",
        "wrong_message",
        "valid_signature_wrong_geometry",
        "valid_signature_wrong_transform",
        "stolen_signing_authority_only",
        "stolen_fragment_only",
        "correct_geometry_wrong_agent_id",
    ],
    "attack_scale_1024": [
        "fake_agent_early",
        "fake_agent_middle",
        "fake_agent_late",
        "valid_signature_wrong_geometry_early",
        "valid_signature_wrong_geometry_middle",
        "valid_signature_wrong_geometry_late",
        "replay_early",
        "replay_late",
    ],
    "fuzz_10000": [
        "fuzz_malformed_packet",
        "fuzz_mixed_packet_set",
        "fuzz_replay_mutation",
    ],
}


BASELINE_MATRIX_SCENARIOS = [
    "honest",
    "fake_agent",
    "unregistered_fake_agent",
    "replay",
    "wrong_message",
    "overbudget",
    "underbudget",
    "malformed",
    "duplicate",
    "missing",
    "valid_signature_wrong_geometry",
    "valid_signature_wrong_transform",
    "stolen_signing_authority_only",
    "stolen_fragment_only",
    "correct_geometry_wrong_agent_id",
]


ABLATION_MODES: dict[str, VerifierOptions] = {
    "usag_full": VerifierOptions(),
    "usag_without_message_hash_binding": VerifierOptions(bind_message_hash=False),
    "usag_without_sender_receiver_binding": VerifierOptions(
        bind_message_hash=False,
        bind_response=False,
    ),
    "usag_without_epoch_nonce_binding": VerifierOptions(
        bind_epoch=False,
        bind_challenge=False,
    ),
    "usag_without_proof_envelope_budget": VerifierOptions(enforce_proof_envelope=False),
    "usag_without_geometry_check": VerifierOptions(check_geometry=False),
    "usag_without_signatures": VerifierOptions(verify_signatures=False),
}


ABLATION_MATRIX_SCENARIOS = [
    "honest",
    "replay",
    "wrong_message",
    "valid_signature_wrong_geometry",
    "valid_signature_wrong_transform",
    "overbudget",
    "underbudget",
    "fake_agent",
    "stolen_fragment_only",
]


BENCHMARK_PRESETS: dict[str, dict[str, int | str]] = {
    "v0_2_matrix": {"scenario": "v0_2_matrix", "agents": 8, "attempts": 1000},
    "honest_1024": {"scenario": "honest", "agents": 1024, "attempts": 100},
    "attack_scale_1024": {"scenario": "attack_scale_1024", "agents": 1024, "attempts": 100},
    "baseline_matrix": {"scenario": "baseline_matrix", "agents": 8, "attempts": 1000},
    "ablation_matrix": {"scenario": "ablation_matrix", "agents": 8, "attempts": 1000},
    "fuzz_10000": {"scenario": "fuzz_10000", "agents": 8, "attempts": 10000},
    "v0_3_focused_10000": {"scenario": "v0_3_focused_10000", "agents": 8, "attempts": 10000},
}


def run_baseline_report(agent_count: int, fragment_size: int, seed: int) -> list[dict[str, str]]:
    gateway = Gateway.create_swarm(agent_count=agent_count, fragment_size=fragment_size, seed=seed)
    results = [
        evaluate_baseline_mode(mode, "fake_agent", gateway)
        for mode in BASELINE_MODES
    ]
    return [
        {
            "mode": result.mode,
            "scenario": result.scenario,
            "passed": str(result.passed),
            "reason": result.reason,
        }
        for result in results
    ]


def run_baseline_matrix(
    agent_count: int,
    fragment_size: int,
    attempts: int,
    seed: int,
    logger: Optional[RunLogger],
) -> dict[str, object]:
    baseline_results: list[BaselineResult] = []
    usag_summaries: dict[str, object] = {}
    for scenario_name in BASELINE_MATRIX_SCENARIOS:
        usag_results: list[VerificationResult] = []
        for index in range(attempts):
            attempt_seed = seed + index
            gateway = Gateway.create_swarm(
                agent_count=agent_count,
                fragment_size=fragment_size,
                seed=attempt_seed,
            )
            for mode in BASELINE_MODES:
                baseline_results.append(evaluate_baseline_mode(mode, scenario_name, gateway))
            result = SCENARIOS[scenario_name](agent_count, fragment_size, attempt_seed, logger)
            usag_results.append(result)
            baseline_results.append(
                BaselineResult(
                    mode="mode_3_usag_spatial_gate",
                    scenario=scenario_name,
                    passed=result.passed,
                    reason=result.failure_reason or "message_released",
                    latency_ms=result.latency_ms,
                    unauthorized=scenario_name != "honest",
                )
            )
        usag_summaries[scenario_name] = summarize_results(usag_results, scenario_name)
    return {
        "modes": [*BASELINE_MODES, "mode_3_usag_spatial_gate"],
        "scenarios": BASELINE_MATRIX_SCENARIOS,
        "summary": summarize_baseline_results(baseline_results),
        "usag_scenarios": usag_summaries,
    }


def run_ablation_matrix(
    agent_count: int,
    fragment_size: int,
    attempts: int,
    seed: int,
    logger: Optional[RunLogger],
) -> dict[str, object]:
    by_ablation: dict[str, object] = {}
    for ablation_name, options in ABLATION_MODES.items():
        scenario_metrics: dict[str, object] = {}
        with _verifier_options(options):
            for scenario_name in ABLATION_MATRIX_SCENARIOS:
                results = [
                    SCENARIOS[scenario_name](agent_count, fragment_size, seed + index, logger)
                    for index in range(attempts)
                ]
                scenario_metrics[scenario_name] = summarize_results(results, scenario_name)
        by_ablation[ablation_name] = {
            "options": options.__dict__,
            "scenarios": scenario_metrics,
        }
    return {
        "ablations": by_ablation,
        "scenarios": ABLATION_MATRIX_SCENARIOS,
    }


def run_experiment(
    scenario: str,
    agent_count: int,
    fragment_size: int,
    attempts: int,
    seed: int,
    output_root: Path,
) -> Path:
    special_scenarios = {"baseline_matrix", "ablation_matrix"}
    if scenario in special_scenarios:
        scenario_names: list[str] = []
    elif scenario == "run_all":
        scenario_names = list(SCENARIOS)
    elif scenario in SCENARIO_GROUPS:
        scenario_names = SCENARIO_GROUPS[scenario]
    else:
        if scenario not in SCENARIOS:
            expected = sorted(list(SCENARIOS) + list(SCENARIO_GROUPS) + ["run_all", *special_scenarios])
            raise ValueError(f"unknown scenario {scenario!r}; expected one of {expected}")
        scenario_names = [scenario]

    run_dir = output_root / utc_run_id()
    logger = RunLogger(run_dir)
    config = {
        "scenario": scenario,
        "agent_count": agent_count,
        "fragment_size": fragment_size,
        "attempts": attempts,
        "determinism_commitment": sha256_hex({"kind": "experiment_seed", "seed": seed}),
        "secret_material_redacted": True,
    }
    write_yaml_like(run_dir / "config.yaml", config)
    write_environment(run_dir)
    write_git_commit(run_dir)

    if scenario == "baseline_matrix":
        metrics = {
            "config": config,
            "baseline_comparison": run_baseline_matrix(
                agent_count,
                fragment_size,
                attempts,
                seed,
                logger,
            ),
            "resource_use": process_resource_use(),
        }
        write_metrics(run_dir / "metrics.json", metrics)
        (run_dir / "summary.md").write_text(
            "# Run Summary: baseline_matrix\n\n"
            + json.dumps(metrics["baseline_comparison"]["summary"], indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        return run_dir

    if scenario == "ablation_matrix":
        metrics = {
            "config": config,
            "ablation_comparison": run_ablation_matrix(
                agent_count,
                fragment_size,
                attempts,
                seed,
                logger,
            ),
            "resource_use": process_resource_use(),
        }
        write_metrics(run_dir / "metrics.json", metrics)
        (run_dir / "summary.md").write_text(
            "# Run Summary: ablation_matrix\n\n"
            + json.dumps(metrics["ablation_comparison"]["scenarios"], indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
        return run_dir

    all_metrics: dict[str, object] = {"config": config, "scenarios": {}}
    for scenario_name in scenario_names:
        results = [
            SCENARIOS[scenario_name](agent_count, fragment_size, seed + index, logger)
            for index in range(attempts)
        ]
        all_metrics["scenarios"][scenario_name] = summarize_results(results, scenario_name)  # type: ignore[index]

    all_metrics["baselines"] = run_baseline_report(agent_count, fragment_size, seed)
    all_metrics["resource_use"] = process_resource_use()
    write_metrics(run_dir / "metrics.json", all_metrics)

    if len(scenario_names) == 1:
        write_summary(run_dir / "summary.md", all_metrics["scenarios"][scenario_names[0]])  # type: ignore[index]
    else:
        (run_dir / "summary.md").write_text(
            "# Run Summary: run_all\n\n"
            + json.dumps(all_metrics["scenarios"], indent=2, sort_keys=True)
            + "\n",
            encoding="utf-8",
        )
    return run_dir


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run USAG protocol experiments.")
    parser.add_argument("--scenario", default="honest", help="scenario name, group, or matrix")
    parser.add_argument("--agents", type=int, default=8, help="number of logical agents")
    parser.add_argument("--fragment-size", type=int, default=16, help="coordinates per agent")
    parser.add_argument("--attempts", type=int, default=1, help="attempts per scenario")
    parser.add_argument("--seed", type=int, default=1337, help="deterministic experiment seed")
    parser.add_argument("--output-root", default="runs", help="run artifact directory")
    return parser


def normalize_argv(argv: list[str]) -> list[str]:
    if not argv or argv[0] != "benchmark":
        return argv
    if len(argv) < 2:
        expected = ", ".join(sorted(BENCHMARK_PRESETS))
        raise ValueError(f"benchmark requires a name; expected one of {expected}")
    benchmark_name = argv[1]
    if benchmark_name not in BENCHMARK_PRESETS:
        expected = ", ".join(sorted(BENCHMARK_PRESETS))
        raise ValueError(f"unknown benchmark {benchmark_name!r}; expected one of {expected}")
    preset = BENCHMARK_PRESETS[benchmark_name]
    remaining = argv[2:]
    normalized = ["--scenario", str(preset["scenario"])]
    if not _has_option(remaining, "--agents"):
        normalized.extend(["--agents", str(preset["agents"])])
    if not _has_option(remaining, "--attempts"):
        normalized.extend(["--attempts", str(preset["attempts"])])
    normalized.extend(remaining)
    return normalized


def _has_option(argv: list[str], option: str) -> bool:
    return any(value == option or value.startswith(f"{option}=") for value in argv)


def main(argv: Optional[list[str]] = None) -> None:
    normalized = normalize_argv(sys.argv[1:] if argv is None else list(argv))
    args = build_parser().parse_args(normalized)
    run_dir = run_experiment(
        scenario=args.scenario,
        agent_count=args.agents,
        fragment_size=args.fragment_size,
        attempts=args.attempts,
        seed=args.seed,
        output_root=Path(args.output_root),
    )
    print(run_dir)


if __name__ == "__main__":
    main()
