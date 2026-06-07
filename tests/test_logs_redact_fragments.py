from pathlib import Path

from spatial_swarm.core.gateway import Gateway
from spatial_swarm.experiments.report import RunLogger


def test_logs_do_not_contain_raw_fragments_or_private_keys(tmp_path: Path):
    logger = RunLogger(tmp_path / "run")
    gateway = Gateway.create_swarm(agent_count=4, fragment_size=8, seed=8, logger=logger)

    result = gateway.send("agent_001", "agent_002", {"body": "log"})

    assert result.passed
    logs = (tmp_path / "run" / "events.jsonl").read_text(encoding="utf-8")
    forbidden = ["\"coords\"", "\"fragment\"", "private_key", "signing_key", "plaintext", "decrypted"]
    for marker in forbidden:
        assert marker not in logs
