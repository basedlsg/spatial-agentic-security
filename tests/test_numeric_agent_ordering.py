from spatial_swarm.core.gateway import Gateway
from spatial_swarm.core.registry import _agent_sort_key


def test_numeric_agent_sort_key_orders_unpadded_ids():
    assert sorted(["agent_10", "agent_2"], key=_agent_sort_key) == ["agent_2", "agent_10"]
    assert sorted(["agent_100", "agent_99"], key=_agent_sort_key) == ["agent_99", "agent_100"]


def test_agent_1024_is_final_in_large_swarm():
    gateway = Gateway.create_swarm(agent_count=1024, fragment_size=1, seed=23)

    assert gateway.registry.original_agent_ids[-1] == "agent_1024"
