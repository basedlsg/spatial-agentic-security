from spatial_swarm.core.errors import FailureReason
from spatial_swarm.core.gateway import Gateway
from spatial_swarm.protocol.proof_packet import ProofPacket


def test_wrong_epoch_fails():
    gateway = Gateway.create_swarm(agent_count=4, fragment_size=8, seed=15)

    def provider(gateway, message, challenge):
        packets = gateway.collect_honest_packets(message, challenge)
        fields = packets[0].as_dict()
        fields["epoch"] = "epoch_9999"
        return [ProofPacket(**fields)] + packets[1:]

    result = gateway.send("agent_001", "agent_002", {"body": "epoch"}, packet_provider=provider)

    assert not result.passed
    assert result.failure_reason == FailureReason.WRONG_EPOCH.value
