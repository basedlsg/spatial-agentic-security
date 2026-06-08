from spatial_swarm.experiments.runner import (
    run_replay_early,
    run_replay_late,
    run_valid_signature_wrong_geometry_early,
    run_valid_signature_wrong_geometry_late,
    run_valid_signature_wrong_message_hash_early,
    run_valid_signature_wrong_message_hash_late,
)


def _failure_event(result):
    return next(event for event in result.events if event.event_type == "proof_failed")


def test_stage_metrics_capture_early_and_late_geometry_failure_position():
    early = run_valid_signature_wrong_geometry_early(8, 8, 24, None)
    late = run_valid_signature_wrong_geometry_late(8, 8, 24, None)

    early_event = _failure_event(early)
    late_event = _failure_event(late)

    assert early_event.failure_stage == "geometry"
    assert early_event.packets_checked_before_failure == 1
    assert early_event.signatures_verified == 1
    assert early_event.decryptions_performed == 1
    assert early_event.geometry_checks_performed == 1

    assert late_event.failure_stage == "geometry"
    assert late_event.packets_checked_before_failure == 8
    assert late_event.signatures_verified == 8
    assert late_event.decryptions_performed == 8
    assert late_event.geometry_checks_performed == 8


def test_stage_metrics_show_message_hash_rejection_before_signature():
    early = run_valid_signature_wrong_message_hash_early(8, 8, 25, None)
    late = run_valid_signature_wrong_message_hash_late(8, 8, 25, None)

    early_event = _failure_event(early)
    late_event = _failure_event(late)

    assert early_event.failure_stage == "message_binding"
    assert early_event.packets_checked_before_failure == 1
    assert early_event.signatures_verified == 0
    assert early_event.decryptions_performed == 0
    assert early_event.geometry_checks_performed == 0

    assert late_event.failure_stage == "message_binding"
    assert late_event.packets_checked_before_failure == 8
    assert late_event.signatures_verified == 7
    assert late_event.decryptions_performed == 7
    assert late_event.geometry_checks_performed == 7


def test_replay_position_variants_capture_packet_position():
    early = run_replay_early(8, 8, 31, None)
    late = run_replay_late(8, 8, 31, None)

    early_event = _failure_event(early)
    late_event = _failure_event(late)

    assert early_event.failure_stage == "message_binding"
    assert early_event.packets_checked_before_failure == 1
    assert early_event.signatures_verified == 0

    assert late_event.failure_stage == "message_binding"
    assert late_event.packets_checked_before_failure == 8
    assert late_event.signatures_verified == 7
