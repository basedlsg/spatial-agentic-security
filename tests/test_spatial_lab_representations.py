"""Representation ladder R0..R4 and entropy accounting."""

from __future__ import annotations

import math
import random

import pytest

from spatial_swarm.spatial_lab import commit as C
from spatial_swarm.spatial_lab import entropy as E
from spatial_swarm.spatial_lab import representations as Rep
from spatial_swarm.spatial_lab import shapes as S

PARAMS = {"R0": {"m": 4096}, "R1": {"p": 17}, "R2": {"mode": "grown"}, "R3": {"mode": "grown"}, "R4": {"mode": "grown"}}


@pytest.mark.parametrize("repr_name", Rep.REPRESENTATIONS)
def test_build_swarm_pieces_open_their_commitments(repr_name):
    rng = random.Random(3)
    sw = Rep.build_swarm(repr_name, rng, 4, 5, PARAMS[repr_name], "swarm-x")
    assert sw.n == 4 and sw.k == 5
    for aid, piece in sw.pieces.items():
        assert len(piece) == 5
        assert C.opens(sw.commitments[aid], "swarm-x", aid, repr_name, piece)
        # a wrong secret does not open
        assert not C.opens(sw.commitments[aid], "swarm-x", aid, repr_name, frozenset())


def test_voxel_pieces_are_connected_and_tile_target():
    rng = random.Random(5)
    sw = Rep.build_swarm("R2", rng, 4, 5, {"mode": "grown"}, "s")
    union = set()
    for piece in sw.pieces.values():
        assert S.is_connected(piece)
        union |= set(piece)
    assert union == set(sw.target)


def test_published_constraints_by_rung():
    rng = random.Random(7)
    r2 = Rep.build_swarm("R2", rng, 3, 4, {"mode": "grown"}, "s")
    assert "target" in r2.public and "connectors" not in r2.public
    r3 = Rep.build_swarm("R3", random.Random(7), 3, 4, {"mode": "grown"}, "s")
    assert "connectors" in r3.public and "topology" not in r3.public
    r4 = Rep.build_swarm("R4", random.Random(7), 3, 4, {"mode": "grown"}, "s")
    assert "connectors" in r4.public and "topology" in r4.public


def test_determinism():
    a = Rep.build_swarm("R3", random.Random(11), 3, 4, {"mode": "grown"}, "s")
    b = Rep.build_swarm("R3", random.Random(11), 3, 4, {"mode": "grown"}, "s")
    assert a.pieces == b.pieces
    assert a.commitments == b.commitments


def test_entropy_closed_form_and_monotonicity():
    assert E.log2_comb(5, 2) == pytest.approx(math.log2(10), abs=1e-9)
    assert Rep.commitment_only_entropy("R0", 4, 8, {"m": 2**16}).secret_space_bits == pytest.approx(
        E.log2_comb(2**16, 8), abs=1e-6
    )
    # smallest alphabet reaching a target bit-length
    m = E.smallest_alphabet_for_bits(8, 100.0)
    assert E.log2_comb(m, 8) >= 100.0
    assert E.log2_comb(m - 1, 8) < 100.0


def test_entropy_bands_overlap_helper():
    accts = [
        E.EntropyAccount("R0", 100.0, "", False),
        E.EntropyAccount("R1", 100.3, "", False),
    ]
    assert E.bands_overlap(accts, 0.5)
    accts.append(E.EntropyAccount("R2", 130.0, "", True))
    assert not E.bands_overlap(accts, 0.5)
