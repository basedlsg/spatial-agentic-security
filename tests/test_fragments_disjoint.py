from spatial_swarm.geometry.finite_grid import FiniteGrid
from spatial_swarm.geometry.fragment import generate_disjoint_fragments


def test_fragment_generation_is_deterministic_under_seed():
    a = generate_disjoint_fragments(8, 16, 123, FiniteGrid())
    b = generate_disjoint_fragments(8, 16, 123, FiniteGrid())

    assert {key: value.coords for key, value in a.items()} == {key: value.coords for key, value in b.items()}


def test_fragments_are_disjoint():
    fragments = generate_disjoint_fragments(32, 16, 123, FiniteGrid())
    seen = set()
    for fragment in fragments.values():
        assert not seen.intersection(fragment.coords)
        seen.update(fragment.coords)
    assert len(seen) == 32 * 16
