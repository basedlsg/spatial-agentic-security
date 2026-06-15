"""Spatial-hardness comparison: random vs 3D secrets, commitment scheme fixed."""

from __future__ import annotations

from spatial_swarm.experiments.spatial_hardness import run_spatial_hardness

R = run_spatial_hardness(seed=7)


def test_assembly_complement_recovers_geometry_not_random():
    e2 = R["e2_assembly_complement"]
    # random secrets are independent: observing target + all others recovers nothing
    assert e2["random"]["exact_recoveries"] == 0
    assert e2["random"]["candidate_count"] > 1
    # the missing piece of a shared 3D object is exactly its complement
    assert e2["points3d"]["exact_recoveries"] == e2["points3d"]["trials"]
    assert e2["voxel"]["exact_recoveries"] == e2["voxel"]["trials"]
    assert e2["points3d"]["candidate_count"] == 1
    assert e2["voxel"]["candidate_count"] == 1


def test_observation_shrinks_geometry_candidates_but_not_random():
    e3 = R["e3_partial_observation"]
    # random: candidate count flat regardless of how many other pieces are seen
    rnd = [row["candidates"] for row in e3["random"]]
    assert len(set(rnd)) == 1
    # geometry: candidates strictly decrease as more pieces are observed, to 1
    for scheme in ("voxel_connected", "points3d"):
        cands = [row["candidates"] for row in e3[scheme]]
        assert cands == sorted(cands, reverse=True)
        assert cands[-1] == 1
        assert cands[0] > 1


def test_public_transform_is_invertible_from_one_observation():
    e4 = R["e4_transform_inversion"]
    assert e4["exact_recoveries"] == e4["trials"]
    assert e4["observations"] == 1


def test_commitment_only_domain_is_not_larger_for_geometry():
    bits = R["e1_bruteforce"]["realistic_domain_bits"]
    # at these parameters the voxel and point domains are not larger than random
    assert bits["voxel_16^3_k16"] < bits["random_m2^32_k16"]
    assert bits["points_p257_k16"] < bits["random_m2^32_k16"]
