from spatial_swarm.core.errors import FailureReason
from spatial_swarm.core.gateway import Gateway


def test_missing_piece_fails():
    gateway = Gateway.create_swarm(agent_count=4, fragment_size=8, seed=5)

    def provider(gateway, message, challenge):
        return gateway.collect_honest_packets(message, challenge)[:-1]

    result = gateway.send("agent_001", "agent_002", {"body": "missing"}, packet_provider=provider)

    assert not result.passed
    assert result.failure_reason == FailureReason.MISSING_PACKET.value
    assert result.ejection is not None
    assert result.ejection.agent_id == "agent_004"
