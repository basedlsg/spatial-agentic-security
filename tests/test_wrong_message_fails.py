from spatial_swarm.attacks.wrong_message_agent import WrongMessageAgent
from spatial_swarm.core.errors import FailureReason
from spatial_swarm.core.gateway import Gateway


def test_wrong_message_proof_fails():
    gateway = Gateway.create_swarm(agent_count=4, fragment_size=8, seed=3)
    other_message = gateway.freeze("agent_001", "agent_002", {"body": "other"}, nonce="other")
    other_challenge = gateway.challenge(other_message)
    wrong = WrongMessageAgent()

    result = gateway.send(
        "agent_001",
        "agent_002",
        {"body": "current"},
        nonce="current",
        packet_provider=lambda gateway, _message, _challenge: wrong.packets_for_other_message(
            gateway,
            other_message,
            other_challenge,
        ),
    )

    assert not result.passed
    assert result.failure_reason == FailureReason.WRONG_MESSAGE_HASH.value
