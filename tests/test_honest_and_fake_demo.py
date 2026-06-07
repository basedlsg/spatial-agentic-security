from spatial_swarm.attacks.fake_agent import RandomFakeAgent
from spatial_swarm.core.errors import FailureReason
from spatial_swarm.core.gateway import Gateway


def test_honest_swarm_passes():
    gateway = Gateway.create_swarm(agent_count=8, fragment_size=16, seed=10)

    result = gateway.send("agent_001", "agent_002", {"body": "honest"})

    assert result.passed
    assert result.released_message == {"body": "honest"}
    assert not result.collapsed


def test_fake_replacement_blocks_and_collapses():
    gateway = Gateway.create_swarm(agent_count=8, fragment_size=16, seed=11)
    fake = RandomFakeAgent("agent_004", seed=12)

    result = gateway.send(
        "agent_001",
        "agent_002",
        {"body": "fake"},
        packet_provider=fake.replace_agent_packets,
    )

    assert not result.passed
    assert result.failure_reason == FailureReason.WRONG_SIGNATURE.value
    assert result.ejection is not None
    assert result.ejection.agent_id == "agent_004"
    assert result.collapsed
