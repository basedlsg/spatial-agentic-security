from spatial_swarm.attacks.duplicate_agent import DuplicateAgent
from spatial_swarm.core.errors import FailureReason
from spatial_swarm.core.gateway import Gateway


def test_duplicate_submission_ejects_and_collapses():
    gateway = Gateway.create_swarm(agent_count=4, fragment_size=8, seed=4)
    duplicate = DuplicateAgent("agent_001")

    result = gateway.send("agent_001", "agent_002", {"body": "duplicate"}, packet_provider=duplicate.packets)

    assert not result.passed
    assert result.failure_reason == FailureReason.DUPLICATE_SUBMISSION.value
    assert result.ejection is not None
    assert result.ejection.agent_id == "agent_001"
    assert result.collapsed
