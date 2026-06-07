import inspect

from spatial_swarm.core.agent import LogicalAgent
from spatial_swarm.core.gateway import Gateway


def test_logical_agent_has_no_direct_receive_api():
    assert not hasattr(LogicalAgent, "receive")
    assert not hasattr(LogicalAgent, "send_direct")


def test_gateway_is_agent_communication_path():
    gateway = Gateway.create_swarm(agent_count=4, fragment_size=8, seed=9)
    agent = gateway.agents["agent_001"]

    assert agent.gateway is gateway
    source = inspect.getsource(LogicalAgent)
    assert ".receive(" not in source
    assert "request_send" in source
