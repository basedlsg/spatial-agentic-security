from spatial_swarm.attacks.replay_agent import ReplayAgent
from spatial_swarm.core.errors import FailureReason
from spatial_swarm.core.gateway import Gateway


def test_replay_old_proofs_fail_for_new_message():
    gateway = Gateway.create_swarm(agent_count=4, fragment_size=8, seed=2)
    old_message = gateway.freeze("agent_001", "agent_002", {"body": "old"}, nonce="old")
    old_challenge = gateway.challenge(old_message)
    old_packets = gateway.collect_honest_packets(old_message, old_challenge)
    replay = ReplayAgent(old_packets)

    result = gateway.send(
        "agent_001",
        "agent_002",
        {"body": "new"},
        nonce="new",
        packet_provider=lambda _gateway, _message, _challenge: replay.packets_for_replay(),
    )

    assert not result.passed
    assert result.failure_reason == FailureReason.WRONG_MESSAGE_HASH.value
    assert result.collapsed
