"""Sealed runtime: restricted API, one-shot, zeroization, attestation stub, redaction."""

from __future__ import annotations

import json

from spatial_swarm.experiments.redaction import scan_text
from spatial_swarm.spatial_puzzle.enclave.process_host import SealedServiceClient, SealedServiceError
from spatial_swarm.spatial_puzzle.enclave.service import SealedService


def test_in_process_lifecycle_and_one_shot():
    svc = SealedService(one_shot=True)
    meta = svc.create_swarm(n=3, k=4, seed=11)
    agent = sorted(meta.commitments)[1]
    pkg = svc.issue_agent_package(meta.swarm_id, agent)
    # correct proof releases
    assert svc.verify_message(meta.swarm_id, agent, pkg.piece).released
    # wrong proof on a fresh swarm destroys it
    svc2 = SealedService(one_shot=True)
    m2 = svc2.create_swarm(n=3, k=4, seed=12)
    a2 = sorted(m2.commitments)[1]
    out = svc2.verify_message(m2.swarm_id, a2, frozenset({(9, 9, 9), (8, 8, 8), (7, 7, 7), (6, 6, 6)}))
    assert out.blocked and out.state == "dead"


def test_destroy_zeroizes():
    svc = SealedService(one_shot=True)
    meta = svc.create_swarm(n=3, k=4, seed=13)
    svc.destroy_swarm(meta.swarm_id)
    assert svc.public_metadata(meta.swarm_id).commitments == {}  # sol dropped


def test_public_metadata_has_no_raw_secret():
    svc = SealedService(one_shot=True, expose_outer_shape=False)
    meta = svc.create_swarm(n=3, k=4, seed=14)
    blob = json.dumps({"swarm_id": meta.swarm_id, "commitments": meta.commitments, "state": meta.state})
    assert scan_text(blob) == []  # commitments are hashes; no coords/keys/seed


def test_attestation_stub_is_not_sgx():
    att = SealedService().attest()
    assert att.sgx is False and att.mode == "stub_local" and att.measurement


def test_process_host_restricts_ops_and_forbids_debug():
    client = SealedServiceClient.start(one_shot=True)
    try:
        meta = client.create_swarm(n=3, k=4, seed=15)
        assert meta.commitments
        # forbidden / debug-style ops are refused by the allowlist
        for bad in ("show_seed", "_swarms", "__dict__", "show_fragment"):
            try:
                client.call(bad)
            except SealedServiceError:
                pass
            else:
                raise AssertionError(f"forbidden op {bad} was not refused")
        att = client.attest()
        assert att.sgx is False
    finally:
        client.shutdown()
    assert not client.is_alive


def test_process_host_one_shot_destroys_across_pipe():
    client = SealedServiceClient.start(one_shot=True)
    try:
        meta = client.create_swarm(n=3, k=4, seed=16)
        agent = sorted(meta.commitments)[1]
        out = client.verify_message(meta.swarm_id, agent, frozenset({(9, 9, 9), (8, 8, 8), (7, 7, 7), (6, 6, 6)}))
        assert out.blocked and out.state == "dead"
    finally:
        client.shutdown()
