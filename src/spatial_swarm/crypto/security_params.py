"""Sizing of the per-agent commitment search space.

The per-agent secret is a set of `fragment_size` distinct points in F_p^3. The
registered commitment H("commit", swarm_id, agent_id, p, coords) is public, so an
attacker that wants to open it without the secret must search the set of possible
coordinate sets. The size of that search space is C(p^3, fragment_size); its base-2
log is the number of bits an exhaustive commitment-preimage search must cover.

These functions report that size so a deployment can choose a `fragment_size`
whose search space meets a target bit-length. They describe the search space; they
do not change protocol behavior.
"""

from __future__ import annotations

from math import lgamma, log

_LOG2 = log(2.0)


def fragment_secret_bits(fragment_size: int, p: int) -> float:
    """log2 C(p**3, fragment_size): bits an exhaustive commitment search covers."""

    if fragment_size <= 0:
        raise ValueError("fragment_size must be positive")
    n = p**3
    if fragment_size > n:
        raise ValueError("fragment_size exceeds grid capacity")
    # log C(n, k) via lgamma to avoid constructing astronomically large integers.
    log_comb = lgamma(n + 1) - lgamma(fragment_size + 1) - lgamma(n - fragment_size + 1)
    return log_comb / _LOG2


def min_fragment_size_for_bits(p: int, target_bits: float) -> int:
    """Smallest fragment_size whose commitment search space reaches target_bits."""

    n = p**3
    size = 1
    while size < n and fragment_secret_bits(size, p) < target_bits:
        size += 1
    return size
