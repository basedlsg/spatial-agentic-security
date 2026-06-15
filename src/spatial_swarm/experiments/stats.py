"""Exact binomial confidence intervals (Clopper-Pearson), no SciPy dependency.

Each benchmark runs `attempts` trials per scenario, each with a distinct seed
(seed + index), so the pass count is a binomial sample. Clopper-Pearson gives an
exact (conservative) interval for the underlying pass probability, including the
boundary cases that dominate here (0 / N and N / N).
"""

from __future__ import annotations

import math

_EPS = 3.0e-16
_FPMIN = 1.0e-300


def _betacf(a: float, b: float, x: float) -> float:
    """Continued fraction for the incomplete beta function (Lentz's method)."""

    qab = a + b
    qap = a + 1.0
    qam = a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < _FPMIN:
        d = _FPMIN
    d = 1.0 / d
    h = d
    for m in range(1, 300):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < _FPMIN:
            d = _FPMIN
        c = 1.0 + aa / c
        if abs(c) < _FPMIN:
            c = _FPMIN
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < _FPMIN:
            d = _FPMIN
        c = 1.0 + aa / c
        if abs(c) < _FPMIN:
            c = _FPMIN
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < _EPS:
            break
    return h


def regularized_incomplete_beta(a: float, b: float, x: float) -> float:
    """I_x(a, b), the regularized incomplete beta function."""

    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    log_beta = math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
    front = math.exp(log_beta + a * math.log(x) + b * math.log(1.0 - x))
    if x < (a + 1.0) / (a + b + 2.0):
        return front * _betacf(a, b, x) / a
    return 1.0 - front * _betacf(b, a, 1.0 - x) / b


def _beta_quantile(q: float, a: float, b: float) -> float:
    """Inverse of I_x(a, b) in x, by bisection (I_x is monotone increasing)."""

    lo, hi = 0.0, 1.0
    for _ in range(200):
        mid = 0.5 * (lo + hi)
        if regularized_incomplete_beta(a, b, mid) < q:
            lo = mid
        else:
            hi = mid
    return 0.5 * (lo + hi)


def clopper_pearson(successes: int, n: int, alpha: float = 0.05) -> tuple[float, float]:
    """Exact (1 - alpha) Clopper-Pearson interval for a binomial proportion."""

    if n <= 0:
        return (0.0, 1.0)
    if successes < 0 or successes > n:
        raise ValueError("successes must be in [0, n]")
    lower = 0.0 if successes == 0 else _beta_quantile(alpha / 2.0, successes, n - successes + 1)
    upper = 1.0 if successes == n else _beta_quantile(1.0 - alpha / 2.0, successes + 1, n - successes)
    return (lower, upper)
