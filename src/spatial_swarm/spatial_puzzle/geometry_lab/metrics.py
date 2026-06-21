"""Metrics helpers for the geometry lab."""

from __future__ import annotations

import csv
import math
import statistics
from collections import Counter
from pathlib import Path
from typing import Iterable


def rate(successes: int, n: int) -> dict[str, float | int]:
    return {"successes": successes, "n": n, "rate": successes / n if n else 0.0}


def summary_values(values: Iterable[float]) -> dict[str, float]:
    ordered = sorted(float(value) for value in values)
    if not ordered:
        return {"min": 0.0, "p50": 0.0, "p95": 0.0, "max": 0.0}
    return {
        "min": ordered[0],
        "p50": statistics.median(ordered),
        "p95": ordered[min(len(ordered) - 1, math.ceil(0.95 * len(ordered)) - 1)],
        "max": ordered[-1],
    }


def summarize_decisions(rows: list[dict]) -> dict:
    attempts = len(rows)
    releases = sum(1 for row in rows if row["released"])
    blocked = sum(1 for row in rows if row["blocked"])
    reasons = Counter(reason for row in rows for reason in row.get("internal_reasons", ()))
    return {
        "attempts": attempts,
        "release": rate(releases, attempts),
        "blocked": rate(blocked, attempts),
        "verification_runtime_ms": summary_values(row["verification_runtime_ms"] for row in rows),
        "checks_performed": summary_values(row["checks_performed"] for row in rows),
        "internal_reasons": dict(sorted(reasons.items())),
    }


def write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("", encoding="utf-8")
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def geometry_value_score(
    *,
    attack_block_rate: float,
    false_block_rate: float,
    runtime_p95_ms: float,
    leakage_bits_lost_a3: float,
    target_bits_a0: float,
) -> dict[str, float]:
    runtime_cost_penalty = min(0.30, runtime_p95_ms / 250.0)
    leakage_penalty = leakage_bits_lost_a3 / max(1.0, target_bits_a0)
    score = attack_block_rate - false_block_rate - runtime_cost_penalty - leakage_penalty
    return {
        "attacks_blocked_by_geometry": attack_block_rate,
        "false_block_penalty": false_block_rate,
        "runtime_cost_penalty": runtime_cost_penalty,
        "leakage_penalty": leakage_penalty,
        "geometry_value_score": score,
    }
