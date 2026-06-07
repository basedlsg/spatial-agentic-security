from spatial_swarm.attacks.fake_agent import RandomFakeAgent
from spatial_swarm.core.errors import FailureReason
from spatial_swarm.core.gateway import Gateway


def test_unregistered_fake_agent_fails_before_signature():
    gateway = Gateway.create_swarm(agent_count=4, fragment_size=8, seed=21)
    fake = RandomFakeAgent("agent_999", seed=22)

    result = gateway.send(
        "agent_001",
        "agent_002",
        {"body": "unregistered fake"},
        packet_provider=lambda gateway, message, challenge: [fake.packet(gateway, message, challenge)],
    )

    assert not result.passed
    assert result.failure_reason == FailureReason.UNREGISTERED_AGENT.value
