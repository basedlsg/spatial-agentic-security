from spatial_swarm.core.gateway import Gateway
from spatial_swarm.geometry.assembly import assembles_committed_piece_set, assembles_exactly


def test_assembly_requires_all_fragments():
    gateway = Gateway.create_swarm(agent_count=4, fragment_size=8, seed=1)
    message = gateway.freeze("agent_001", "agent_002", {"body": "hello"})
    challenge = gateway.challenge(message)
    submitted = {
        agent_id: challenge.transform.apply(gateway.sidecars[agent_id].fragment.coords)
        for agent_id in gateway.registry.original_agent_ids
    }
    raw_fragments = {
        agent_id: gateway.sidecars[agent_id].fragment
        for agent_id in gateway.registry.original_agent_ids
    }

    assert assembles_exactly(submitted, raw_fragments, challenge.transform)
    assert assembles_committed_piece_set(submitted, gateway.registry.original_agent_ids)

    submitted.pop("agent_004")
    assert not assembles_exactly(submitted, raw_fragments, challenge.transform)
    assert not assembles_committed_piece_set(submitted, gateway.registry.original_agent_ids)
