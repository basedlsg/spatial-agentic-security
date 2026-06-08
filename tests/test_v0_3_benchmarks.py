import json
from pathlib import Path

from spatial_swarm.attacks.fuzzer import MUTATION_KINDS
from spatial_swarm.core.errors import FailureReason
from spatial_swarm.experiments.runner import (
    normalize_argv,
    run_ablation_matrix,
    run_experiment,
    run_fuzz_malformed_packet,
    run_fuzz_mixed_packet_set,
    run_fuzz_replay_mutation,
)


def test_benchmark_command_aliases_requested_clean_rerun_names():
    assert normalize_argv(["benchmark", "v0_2_matrix"]) == [
        "--scenario",
        "v0_2_matrix",
        "--agents",
        "8",
        "--attempts",
        "1000",
    ]
    assert normalize_argv(["benchmark", "honest_1024"]) == [
        "--scenario",
        "honest",
        "--agents",
        "1024",
        "--attempts",
        "100",
    ]
    assert normalize_argv(["benchmark", "attack_scale_1024", "--attempts=2"]) == [
        "--scenario",
        "attack_scale_1024",
        "--agents",
        "1024",
        "--attempts=2",
    ]


def test_baseline_matrix_shows_spatial_layer_adds_geometry_rejection(tmp_path: Path):
    run_dir = run_experiment(
        scenario="baseline_matrix",
        agent_count=4,
        fragment_size=8,
        attempts=1,
        seed=101,
        output_root=tmp_path,
    )
    metrics = json.loads((run_dir / "metrics.json").read_text(encoding="utf-8"))
    summary = metrics["baseline_comparison"]["summary"]
    geometry = summary["by_scenario"]["valid_signature_wrong_geometry"]

    assert geometry["passes_by_mode"]["mode_0_no_gate"] == 1
    assert geometry["passes_by_mode"]["mode_1_sender_signature_only"] == 1
    assert geometry["passes_by_mode"]["mode_2_unanimous_signature_gate"] == 1
    assert geometry["passes_by_mode"]["mode_3_usag_spatial_gate"] == 0


def test_ablation_without_geometry_moves_wrong_geometry_to_later_layer():
    metrics = run_ablation_matrix(
        agent_count=4,
        fragment_size=8,
        attempts=1,
        seed=102,
        logger=None,
    )
    full = metrics["ablations"]["usag_full"]["scenarios"]["valid_signature_wrong_geometry"]
    without_geometry = metrics["ablations"]["usag_without_geometry_check"]["scenarios"][
        "valid_signature_wrong_geometry"
    ]

    assert full["failure_reasons"] == {FailureReason.WRONG_GEOMETRY.value: 1}
    assert FailureReason.WRONG_GEOMETRY.value not in without_geometry["failure_reasons"]
    assert without_geometry["passes"] == 0


def test_fuzzer_mutations_fail_closed_without_crashing():
    for offset in range(len(MUTATION_KINDS)):
        result = run_fuzz_malformed_packet(4, 8, offset, None)
        assert not result.passed, offset
        assert result.failure_reason

    for scenario in (run_fuzz_mixed_packet_set, run_fuzz_replay_mutation):
        result = scenario(4, 8, 203, None)
        assert not result.passed
        assert result.failure_reason
