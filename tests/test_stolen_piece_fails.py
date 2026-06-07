from spatial_swarm.attacks.stolen_piece_agent import PartialSwarmAgent, StolenSinglePieceAgent
from spatial_swarm.core.errors import FailureReason
from spatial_swarm.core.gateway import Gateway


def test_single_stolen_piece_fails():
    gateway = Gateway.create_swarm(agent_count=4, fragment_size=8, seed=16)
    stolen = StolenSinglePieceAgent("agent_001")

    result = gateway.send("agent_001", "agent_002", {"body": "stolen"}, packet_provider=stolen.packets)

    assert not result.passed
    assert result.failure_reason == FailureReason.MISSING_PACKET.value


def test_partial_swarm_fails_for_k_less_than_n():
    gateway = Gateway.create_swarm(agent_count=4, fragment_size=8, seed=17)
    partial = PartialSwarmAgent(controlled_count=3)

    result = gateway.send("agent_001", "agent_002", {"body": "partial"}, packet_provider=partial.packets)

    assert not result.passed
    assert result.failure_reason == FailureReason.MISSING_PACKET.value
