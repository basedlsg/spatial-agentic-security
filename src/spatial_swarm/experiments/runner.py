"""Command-line experiment runner for USAG."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Callable, Optional

from spatial_swarm.attacks.duplicate_agent import DuplicateAgent
from spatial_swarm.attacks.fake_agent import RandomFakeAgent
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
    central_gateway_only,
    direct_communication,
    signature_only_sender,
    unanimous_signature,
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
from spatial_swarm.protocol.verifier import VerificationResult


Scenario = Callable[[int, int, int, Optional[RunLogger]], VerificationResult]


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
    )


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
    "scale_smoke": run_scale_smoke,
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
        "stolen_signing_key_only",
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
        "replay",
        "valid_signature_wrong_geometry",
        "valid_signature_wrong_transform",
        "wrong_message",
        "unregistered_fake_agent",
    ],
}


def run_baseline_report(agent_count: int, fragment_size: int, seed: int) -> list[dict[str, str]]:
    gateway = Gateway.create_swarm(agent_count=agent_count, fragment_size=fragment_size, seed=seed)
    content = {"body": "baseline"}
    results = [
        direct_communication("fake_agent", "agent_002", content),
        central_gateway_only(gateway, "fake_agent", "agent_002", content),
        signature_only_sender(gateway, "agent_001", "agent_002", content, fake=True),
        unanimous_signature(gateway, "agent_001", "agent_002", content),
    ]
    return [{"name": result.name, "passed": str(result.passed), "reason": result.reason} for result in results]


def run_experiment(
    scenario: str,
    agent_count: int,
    fragment_size: int,
    attempts: int,
    seed: int,
    output_root: Path,
) -> Path:
    if scenario == "run_all":
        scenario_names = list(SCENARIOS)
    elif scenario in SCENARIO_GROUPS:
        scenario_names = SCENARIO_GROUPS[scenario]
    else:
        if scenario not in SCENARIOS:
            expected = sorted(list(SCENARIOS) + list(SCENARIO_GROUPS) + ["run_all"])
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
    parser.add_argument("--scenario", default="honest", help="scenario name or run_all")
    parser.add_argument("--agents", type=int, default=8, help="number of logical agents")
    parser.add_argument("--fragment-size", type=int, default=16, help="coordinates per agent")
    parser.add_argument("--attempts", type=int, default=1, help="attempts per scenario")
    parser.add_argument("--seed", type=int, default=1337, help="deterministic experiment seed")
    parser.add_argument("--output-root", default="runs", help="run artifact directory")
    return parser


def main(argv: Optional[list[str]] = None) -> None:
    args = build_parser().parse_args(argv)
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
