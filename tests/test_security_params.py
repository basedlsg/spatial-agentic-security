"""Commitment search-space sizing for the per-agent secret."""

from __future__ import annotations

import pytest

from spatial_swarm.crypto.security_params import (
    fragment_secret_bits,
    min_fragment_size_for_bits,
)


def test_default_fragment_size_search_space():
    # Default config (fragment_size=16, p=257) -> ~340 bits.
    assert fragment_secret_bits(16, 257) == pytest.approx(340.0, abs=1.0)


def test_small_fragment_size_has_low_search_space():
    # fragment_size=1 -> log2(257^3) ~ 24 bits.
    assert fragment_secret_bits(1, 257) == pytest.approx(24.0, abs=0.5)
    assert fragment_secret_bits(1, 257) < 30


def test_bits_increase_with_fragment_size():
    p = 257
    values = [fragment_secret_bits(k, p) for k in range(1, 17)]
    assert values == sorted(values)
    assert all(b < a for a, b in zip(values[1:], values))  # strictly increasing


def test_min_fragment_size_thresholds():
    assert min_fragment_size_for_bits(257, 128) == 6
    assert min_fragment_size_for_bits(257, 256) == 12
    assert fragment_secret_bits(min_fragment_size_for_bits(257, 128), 257) >= 128


def test_invalid_fragment_size():
    with pytest.raises(ValueError):
        fragment_secret_bits(0, 257)
    with pytest.raises(ValueError):
        fragment_secret_bits(257**3 + 1, 257)
