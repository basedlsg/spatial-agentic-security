from spatial_swarm.core.gateway import Gateway
from spatial_swarm.core.sidecar_runtime import ProcessSidecarClient, SidecarRuntimeError
from spatial_swarm.experiments.runner import normalize_argv, run_process_sidecar_fake_agent


def test_process_sidecar_client_exposes_only_minimal_api():
    gateway = Gateway.create_swarm(
        agent_count=2,
        fragment_size=4,
        seed=501,
        sidecar_runtime="process",
    )
    try:
        client = gateway.sidecars["agent_001"]

        assert isinstance(client, ProcessSidecarClient)
        assert client.health_check() == {"status": "ok", "agent_id": "agent_001"}
        assert not hasattr(client, "fragment")
        assert not hasattr(client, "coords")
        assert not hasattr(client, "signing_key")
        assert not hasattr(client, "private_key")
        assert not hasattr(client, "show_fragment")
        assert not hasattr(client, "show_private_key")
        assert not hasattr(client, "show_seed")
    finally:
        gateway.shutdown_sidecars()


def test_process_sidecars_can_release_honest_message_and_shutdown():
    gateway = Gateway.create_swarm(
        agent_count=3,
        fragment_size=4,
        seed=502,
        sidecar_runtime="process",
    )
    try:
        result = gateway.send("agent_001", "agent_002", {"body": "process sidecars"})

        assert result.passed
        assert gateway.active_verifier is None
        assert gateway.last_verifier_shutdown
        assert all(sidecar.is_alive for sidecar in gateway.sidecars.values())
    finally:
        gateway.shutdown_sidecars()

    assert all(not sidecar.is_alive for sidecar in gateway.sidecars.values())


def test_process_sidecar_rejects_submit_after_shutdown():
    gateway = Gateway.create_swarm(
        agent_count=2,
        fragment_size=4,
        seed=503,
        sidecar_runtime="process",
    )
    client = gateway.sidecars["agent_001"]

    gateway.shutdown_sidecars()

    assert not client.is_alive
    try:
        client.health_check()
    except SidecarRuntimeError:
        pass
    else:
        raise AssertionError("expected shut-down sidecar client to reject commands")


def test_process_sidecar_benchmark_alias_and_fake_failure():
    assert normalize_argv(["benchmark", "v0_5_process_sidecar_smoke"]) == [
        "--scenario",
        "v0_5_process_sidecar_smoke",
        "--agents",
        "4",
        "--attempts",
        "10",
    ]

    result = run_process_sidecar_fake_agent(4, 4, 504, None)

    assert not result.passed
    assert result.failure_reason == "wrong_signature"
