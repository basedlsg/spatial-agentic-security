"""Cross-swarm replay: a proof from one swarm must not validate in another.

The gap (found by the security-model audit): the signed payload bound
agent_id/epoch/message_id/challenge_id but NO swarm identity, so two swarms that
reuse key material (e.g. the same seed) accepted each other's proofs. The fix
binds a per-swarm `swarm_id` into the signed payload and the fragment
commitment, with an explicit verifier check.
"""

from __future__ import annotations

from spatial_swarm.core.errors import FailureReason
from spatial_swarm.core.gateway import Gateway


def _honest_packets_from(gateway: Gateway):
    message = gateway.freeze("agent_001", "agent_002", {"body": "replayed"}, nonce="n")
    challenge = gateway.challenge(message)
    return gateway.collect_honest_packets(message, challenge)


def test_proof_from_another_swarm_is_rejected():
    # Same seed => identical keys/fragments/commitments; only swarm_id differs.
    swarm_a = Gateway.create_swarm(agent_count=4, fragment_size=8, seed=42, swarm_id="alpha")
    swarm_b = Gateway.create_swarm(agent_count=4, fragment_size=8, seed=42, swarm_id="beta")
    a_packets = _honest_packets_from(swarm_a)

    result = swarm_b.send(
        "agent_001",
        "agent_002",
        {"body": "replayed"},
        nonce="n",
        packet_provider=lambda g, m, c: a_packets,
    )

    assert not result.passed
    assert result.failure_reason == FailureReason.WRONG_SWARM.value


def test_distinct_swarm_ids_change_the_commitment():
    """swarm_id is bound into the fragment commitment, so identical fragments in
    different swarms commit to different values."""

    swarm_a = Gateway.create_swarm(agent_count=3, fragment_size=8, seed=7, swarm_id="alpha")
    swarm_b = Gateway.create_swarm(agent_count=3, fragment_size=8, seed=7, swarm_id="beta")
    a = swarm_a.registry.require("agent_001")
    b = swarm_b.registry.require("agent_001")
    assert a.verify_key.encode() == b.verify_key.encode()  # same keys (same seed)
    assert a.fragment_commitment != b.fragment_commitment   # but distinct commitments


def test_tampering_swarm_id_breaks_the_signature():
    """Swapping the swarm_id field to pass the swarm check fails the signature,
    since swarm_id is covered by the signed payload."""

    swarm_a = Gateway.create_swarm(agent_count=4, fragment_size=8, seed=42, swarm_id="alpha")
    swarm_b = Gateway.create_swarm(agent_count=4, fragment_size=8, seed=42, swarm_id="beta")

    a_packets = _honest_packets_from(swarm_a)
    # Rewrite each packet's swarm_id to beta (passes swarm binding) without re-signing.
    tampered = []
    for packet in a_packets:
        fields = packet.as_dict()
        fields["swarm_id"] = "beta"
        tampered.append(packet.__class__(**fields))

    result = swarm_b.send(
        "agent_001",
        "agent_002",
        {"body": "replayed"},
        nonce="n",
        packet_provider=lambda g, m, c: tampered,
    )

    assert not result.passed
    assert result.failure_reason == FailureReason.WRONG_SIGNATURE.value


def test_same_swarm_id_still_interoperates_documents_the_residual():
    """If two swarms share both seed AND swarm_id they are the same swarm and
    interoperate -- so domain separation requires deployments to pass a unique
    swarm_id (the default is seed-derived for reproducibility)."""

    swarm_a = Gateway.create_swarm(agent_count=4, fragment_size=8, seed=42, swarm_id="same")
    swarm_b = Gateway.create_swarm(agent_count=4, fragment_size=8, seed=42, swarm_id="same")
    a_packets = _honest_packets_from(swarm_a)

    result = swarm_b.send(
        "agent_001",
        "agent_002",
        {"body": "replayed"},
        nonce="n",
        packet_provider=lambda g, m, c: a_packets,
    )
    assert result.passed  # identical identity == same swarm


def test_default_swarm_id_is_deterministic_from_seed():
    a = Gateway.create_swarm(agent_count=2, fragment_size=4, seed=99)
    b = Gateway.create_swarm(agent_count=2, fragment_size=4, seed=99)
    assert a.swarm_id == b.swarm_id  # reproducible
    c = Gateway.create_swarm(agent_count=2, fragment_size=4, seed=100)
    assert a.swarm_id != c.swarm_id  # different seed -> different default swarm
