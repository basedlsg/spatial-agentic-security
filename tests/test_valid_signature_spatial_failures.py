from spatial_swarm.attacks.valid_signature_agent import (
    CorrectGeometryWrongAgentIdAgent,
    StolenFragmentOnlyAgent,
    StolenSigningKeyOnlyAgent,
    ValidSignatureWrongGeometryAgent,
    ValidSignatureWrongMessageHashAgent,
    ValidSignatureWrongTransformAgent,
)
from spatial_swarm.core.errors import FailureReason
from spatial_swarm.core.gateway import Gateway


def test_valid_signature_wrong_fragment_geometry_fails_spatial_check():
    gateway = Gateway.create_swarm(agent_count=4, fragment_size=8, seed=18)
    attack = ValidSignatureWrongGeometryAgent("agent_004", "agent_003")

    result = gateway.send(
        "agent_001",
        "agent_002",
        {"body": "valid signature wrong geometry"},
        packet_provider=attack.replace_agent_packets,
    )

    assert not result.passed
    assert result.failure_reason == FailureReason.WRONG_GEOMETRY.value


def test_valid_signature_wrong_transform_fails_spatial_check():
    gateway = Gateway.create_swarm(agent_count=4, fragment_size=8, seed=19)
    attack = ValidSignatureWrongTransformAgent("agent_004", "agent_003")

    result = gateway.send(
        "agent_001",
        "agent_002",
        {"body": "valid signature wrong transform"},
        packet_provider=attack.replace_agent_packets,
    )

    assert not result.passed
    assert result.failure_reason == FailureReason.WRONG_GEOMETRY.value


def test_valid_signature_correct_geometry_wrong_message_hash_fails_binding_first():
    gateway = Gateway.create_swarm(agent_count=4, fragment_size=8, seed=20)
    attack = ValidSignatureWrongMessageHashAgent("agent_004", "agent_003")

    result = gateway.send(
        "agent_001",
        "agent_002",
        {"body": "valid signature wrong message hash"},
        packet_provider=attack.replace_agent_packets,
    )

    assert not result.passed
    assert result.failure_reason == FailureReason.WRONG_MESSAGE_HASH.value


def test_stolen_signing_key_only_fails_geometry():
    gateway = Gateway.create_swarm(agent_count=4, fragment_size=8, seed=27)
    attack = StolenSigningKeyOnlyAgent("agent_004", "agent_003")

    result = gateway.send(
        "agent_001",
        "agent_002",
        {"body": "stolen signing key only"},
        packet_provider=attack.replace_agent_packets,
    )

    assert not result.passed
    assert result.failure_reason == FailureReason.WRONG_GEOMETRY.value


def test_stolen_fragment_only_fails_signature():
    gateway = Gateway.create_swarm(agent_count=4, fragment_size=8, seed=28)
    attack = StolenFragmentOnlyAgent("agent_004", seed=29)

    result = gateway.send(
        "agent_001",
        "agent_002",
        {"body": "stolen fragment only"},
        packet_provider=attack.replace_agent_packets,
    )

    assert not result.passed
    assert result.failure_reason == FailureReason.WRONG_SIGNATURE.value


def test_correct_geometry_wrong_agent_id_fails_response_binding():
    gateway = Gateway.create_swarm(agent_count=4, fragment_size=8, seed=30)
    attack = CorrectGeometryWrongAgentIdAgent("agent_004", "agent_003")

    result = gateway.send(
        "agent_001",
        "agent_002",
        {"body": "correct geometry wrong agent id"},
        packet_provider=attack.replace_agent_packets,
    )

    assert not result.passed
    assert result.failure_reason == FailureReason.RESPONSE_BINDING_FAILED.value
