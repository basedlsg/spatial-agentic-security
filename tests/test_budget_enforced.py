from spatial_swarm.attacks.overbudget_agent import OverBudgetAgent, UnderBudgetAgent
from spatial_swarm.attacks.slow_agent import SlowAgent
from spatial_swarm.core.errors import FailureReason
from spatial_swarm.core.gateway import Gateway


def test_overbudget_packet_fails_before_signature():
    gateway = Gateway.create_swarm(agent_count=4, fragment_size=8, seed=6)
    attack = OverBudgetAgent("agent_001")

    result = gateway.send("agent_001", "agent_002", {"body": "over"}, packet_provider=attack.replace_agent_packets)

    assert not result.passed
    assert result.failure_reason == FailureReason.OVER_BUDGET.value


def test_late_packet_fails():
    gateway = Gateway.create_swarm(agent_count=4, fragment_size=8, seed=7)
    attack = SlowAgent("agent_001")

    result = gateway.send("agent_001", "agent_002", {"body": "slow"}, packet_provider=attack.replace_agent_packets)

    assert not result.passed
    assert result.failure_reason == FailureReason.LATE_PACKET.value


def test_underbudget_packet_fails():
    gateway = Gateway.create_swarm(agent_count=4, fragment_size=8, seed=14)
    attack = UnderBudgetAgent("agent_001")

    result = gateway.send(
        "agent_001",
        "agent_002",
        {"body": "under"},
        packet_provider=attack.replace_agent_packets,
    )

    assert not result.passed
    assert result.failure_reason == FailureReason.UNDER_BUDGET.value
