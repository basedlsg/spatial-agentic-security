import numpy as np
from hypothesis import given, strategies as st

from spatial_swarm.geometry.transform import transform_from_challenge


@given(st.text(min_size=1, max_size=64), st.tuples(st.integers(0, 256), st.integers(0, 256), st.integers(0, 256)))
def test_transform_inverse_recovers_coord(seed_text, coord):
    transform = transform_from_challenge(seed_text, 257)
    inverse = transform.inverse()

    assert inverse.apply_coord(transform.apply_coord(coord)) == coord


def test_transform_matrix_is_invertible():
    transform = transform_from_challenge("challenge", 257)
    inverse = transform.inverse()

    identity = (transform.matrix.astype(int) @ inverse.matrix.astype(int)) % 257
    assert np.array_equal(identity, np.eye(3, dtype=int) % 257)
