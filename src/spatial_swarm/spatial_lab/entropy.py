"""Entropy accounting and matching across representations.

Two numbers, never conflated:
- commitment-only entropy: log2 of the number of possible secrets an attacker with
  NO observation must search (the brute-force-against-commitment cost).
- given-public-structure entropy: log2 of the consistent-candidate count after the
  attacker uses the published constraints (computed by the Lab B solver, not here).

Set-based (R0/R1) and shape-based (R2-R4) secrets are matched only on commitment-only
entropy -- the one common currency. For shape representations the connected-polycube
count is hard to count exactly, so an upper bound log2 C(bounding-volume, k) is used
and flagged `is_upper_bound`.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import lgamma, log

_LOG2 = log(2.0)


def log2_comb(n: int, k: int) -> float:
    if k < 0 or k > n or n < 0:
        return float("-inf")
    return (lgamma(n + 1) - lgamma(k + 1) - lgamma(n - k + 1)) / _LOG2


@dataclass(frozen=True)
class EntropyAccount:
    repr_name: str
    secret_space_bits: float
    basis: str
    is_upper_bound: bool


def smallest_alphabet_for_bits(k: int, target_bits: float, cap: int = 2**40) -> int:
    """Smallest M with log2 C(M, k) >= target_bits (for the R0 random alphabet)."""

    lo, hi = k, k
    while log2_comb(hi, k) < target_bits and hi < cap:
        hi *= 2
    while lo < hi:
        mid = (lo + hi) // 2
        if log2_comb(mid, k) >= target_bits:
            hi = mid
        else:
            lo = mid + 1
    return lo


def bands_overlap(accounts: list[EntropyAccount], tolerance_bits: float = 0.5) -> bool:
    """True if all representations' entropy bits lie within `tolerance_bits` of each other."""

    bits = [a.secret_space_bits for a in accounts if a.secret_space_bits != float("-inf")]
    if len(bits) < 2:
        return True
    return max(bits) - min(bits) <= tolerance_bits
