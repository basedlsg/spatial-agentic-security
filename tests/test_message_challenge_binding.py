from spatial_swarm.core.gateway import Gateway


def test_message_hash_changes_when_message_changes():
    gateway = Gateway.create_swarm(agent_count=4, fragment_size=8, seed=12)

    a = gateway.freeze("agent_001", "agent_002", {"body": "a"}, nonce="same")
    b = gateway.freeze("agent_001", "agent_002", {"body": "b"}, nonce="same")

    assert a.message_id != b.message_id


def test_sender_receiver_and_epoch_change_challenge():
    gateway = Gateway.create_swarm(agent_count=4, fragment_size=8, seed=13)

    forward = gateway.freeze("agent_001", "agent_002", {"body": "same"}, nonce="same")
    reverse = gateway.freeze("agent_002", "agent_001", {"body": "same"}, nonce="same")
    other_epoch = gateway.freeze("agent_001", "agent_002", {"body": "same"}, nonce="same")
    object.__setattr__(other_epoch, "epoch", "epoch_9999")

    assert gateway.challenge(forward).challenge_id != gateway.challenge(reverse).challenge_id
    assert gateway.challenge(forward).challenge_id != gateway.challenge(other_epoch).challenge_id
