"""Attackers, prior-observation behavior, and the LLM hook."""

from __future__ import annotations

import random

from spatial_swarm.spatial_lab import attackers as AT
from spatial_swarm.spatial_lab import pose as P
from spatial_swarm.spatial_lab import representations as Rep
from spatial_swarm.spatial_lab.solvers.base import Budget

PARAMS = {"R2": {"mode": "grown"}, "R3": {"mode": "grown"}, "R4": {"mode": "grown"}}


def _swarm(repr_name="R3", seed=3, n=3, k=4):
    return Rep.build_swarm(repr_name, random.Random(seed), n, k, PARAMS[repr_name], "s")


def test_registration_attacker_finds_under_pose():
    sw = _swarm()
    agent = sw.agent_ids()[1]
    obs = [P.apply_pose(P.random_pose(random.Random(1), 2), sw.pieces[agent])]
    out = AT.lab_a_registration(sw, agent, obs, bound=2, budget=Budget(5.0, 5_000_000))
    assert out.found
    assert out.reconstruction is not None and out.reconstruction["iou"] == 1.0
    assert out.pose_space_size == P.pose_space_size(2)


def test_neighbor_copy_fails_lab_a_and_b():
    sw = _swarm()
    agent = sw.agent_ids()[1]
    a = AT.lab_a_neighbor_copy(sw, agent, bound=2, budget=Budget(5.0, 2_000_000))
    b = AT.lab_b_neighbor_copy(sw, agent)
    assert not a.found
    assert not b.found


def test_assembly_observation_shrinks_candidates_monotonically():
    sw = _swarm("R2", seed=5)
    agent = sw.agent_ids()[1]
    counts = []
    for revealed in range(0, sw.n):  # 0 .. n-1 other pieces revealed
        out = AT.lab_b_assembly(sw, agent, revealed, budget=Budget(10.0, 5_000_000), exact=True)
        assert out.found
        counts.append(out.consistent_candidates)
    assert counts == sorted(counts, reverse=True)   # non-increasing as more revealed
    assert counts[-1] == 1                            # all-but-one revealed -> unique piece


def test_random_pose_attacker_is_well_formed():
    sw = _swarm("R2")
    agent = sw.agent_ids()[1]
    obs = [P.apply_pose(P.random_pose(random.Random(2), 3), sw.pieces[agent])]
    out = AT.lab_a_random_pose(sw, agent, obs, bound=3, budget=Budget(0.2, 5000), seed=1)
    assert out.attacker == "random_pose"
    assert isinstance(out.found, bool)


def test_llm_hook_not_run_without_provider():
    sw = _swarm()
    agent = sw.agent_ids()[1]
    out = AT.llm_attacker(sw, agent, None, provider=None)
    assert out.detail["status"] == "not_run"
    assert not out.found


def test_llm_hook_records_raw_output_verbatim():
    sw = _swarm()
    agent = sw.agent_ids()[1]
    raw = "MODEL: my guess <<unparsed junk kept>>"

    def garbage_provider(view) -> AT.LLMResponse:
        # returns a wrong guess; raw output must be stored unchanged
        return AT.LLMResponse(items=[[0, 0, 0]], raw_output=raw, model="stub-1", provider="unit")

    out = AT.llm_attacker(sw, agent, None, provider=garbage_provider)
    assert out.detail["raw_output"] == raw
    assert out.detail["model"] == "stub-1"
    assert not out.found  # wrong guess does not open

    def oracle_provider(view) -> AT.LLMResponse:
        return AT.LLMResponse(items=[list(c) for c in sw.pieces[agent]], raw_output="ok", model="stub-2")

    win = AT.llm_attacker(sw, agent, None, provider=oracle_provider)
    assert win.found  # a correct guess opens (hook plumbing works)
