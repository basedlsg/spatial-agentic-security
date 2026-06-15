"""The fixed commitment scheme shared across representations."""

from __future__ import annotations

from spatial_swarm.spatial_lab import commit as C


def test_round_trip_opens():
    items = {(0, 0, 0), (1, 0, 0), (2, 1, 3)}
    com = C.commit("s", "agent_001", "R2", items)
    assert C.opens(com, "s", "agent_001", "R2", items)


def test_order_independent():
    a = C.commit("s", "agent_001", "R2", [(0, 0, 0), (1, 0, 0), (2, 1, 3)])
    b = C.commit("s", "agent_001", "R2", [(2, 1, 3), (0, 0, 0), (1, 0, 0)])
    assert a == b


def test_coord_tuple_and_list_are_equivalent():
    a = C.commit("s", "agent_001", "R2", {(0, 0, 0), (1, 2, 3)})
    b = C.commit("s", "agent_001", "R2", {(1, 2, 3), (0, 0, 0)})
    assert a == b


def test_int_secret_supported():
    com = C.commit("s", "agent_001", "R0", {7, 42, 1000})
    assert C.opens(com, "s", "agent_001", "R0", {1000, 7, 42})
    assert not C.opens(com, "s", "agent_001", "R0", {7, 42, 999})


def test_distinct_secrets_differ():
    a = C.commit("s", "agent_001", "R2", {(0, 0, 0), (1, 0, 0)})
    b = C.commit("s", "agent_001", "R2", {(0, 0, 0), (1, 0, 1)})
    assert a != b


def test_representation_tag_separates_identical_item_sets():
    items = {(0, 0, 0), (1, 0, 0)}
    assert C.commit("s", "agent_001", "R2", items) != C.commit("s", "agent_001", "R3", items)


def test_agent_and_swarm_bind():
    items = {(0, 0, 0), (1, 0, 0)}
    assert C.commit("s", "agent_001", "R2", items) != C.commit("s", "agent_002", "R2", items)
    assert C.commit("s1", "agent_001", "R2", items) != C.commit("s2", "agent_001", "R2", items)
