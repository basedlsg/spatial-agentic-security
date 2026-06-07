from spatial_swarm.core.gateway import Gateway
from spatial_swarm.geometry.assembly import assembles_exactly


def test_assembly_requires_all_fragments():
    gateway = Gateway.create_swarm(agent_count=4, fragment_size=8, seed=1)
    message = gateway.freeze("agent_001", "agent_002", {"body": "hello"})
    challenge = gateway.challenge(message)
    submitted = {
        agent_id: challenge.transform.apply(registration.fragment.coords)
        for agent_id, registration in [
            (agent_id, gateway.registry.require(agent_id))
            for agent_id in gateway.registry.original_agent_ids
        ]
    }

    assert assembles_exactly(submitted, gateway.registry.original_fragments(), challenge.transform)

    submitted.pop("agent_004")
    assert not assembles_exactly(submitted, gateway.registry.original_fragments(), challenge.transform)
