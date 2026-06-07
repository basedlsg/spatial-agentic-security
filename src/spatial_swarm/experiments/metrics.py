"""Metrics aggregation from run results and JSONL events."""

from __future__ import annotations

import json
import platform
import resource
import statistics
from pathlib import Path
from typing import Any

from spatial_swarm.protocol.verifier import VerificationResult


def summarize_results(results: list[VerificationResult], scenario: str) -> dict[str, Any]:
    attempts = len(results)
    passes = sum(1 for result in results if result.passed)
    failures = attempts - passes
    latencies = [result.latency_ms for result in results]
    proof_totals = [result.proof_bytes_total for result in results]
    failure_reasons: dict[str, int] = {}
    ejections = 0
    collapses = 0
    for result in results:
        if result.failure_reason:
            failure_reasons[result.failure_reason] = failure_reasons.get(result.failure_reason, 0) + 1
        if result.ejection:
            ejections += 1
        if result.collapsed:
            collapses += 1

    return {
        "scenario": scenario,
        "attempts": attempts,
        "passes": passes,
        "failures": failures,
        "pass_rate": passes / attempts if attempts else 0.0,
        "failure_rate": failures / attempts if attempts else 0.0,
        "ejections": ejections,
        "swarm_collapse_rate": collapses / attempts if attempts else 0.0,
        "failure_reasons": failure_reasons,
        "latency_ms": _latency_summary(latencies),
        "proof_bytes_total": _latency_summary(proof_totals),
    }


def _latency_summary(values: list[float]) -> dict[str, float]:
    if not values:
        return {"p50": 0.0, "p95": 0.0, "p99": 0.0, "max": 0.0}
    ordered = sorted(float(value) for value in values)
    return {
        "p50": statistics.median(ordered),
        "p95": ordered[min(len(ordered) - 1, int(0.95 * (len(ordered) - 1)))],
        "p99": ordered[min(len(ordered) - 1, int(0.99 * (len(ordered) - 1)))],
        "max": max(ordered),
    }


def read_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def write_metrics(path: Path, metrics: dict[str, Any]) -> None:
    path.write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_summary(path: Path, metrics: dict[str, Any]) -> None:
    lines = [
        f"# Run Summary: {metrics['scenario']}",
        "",
        f"- attempts: {metrics['attempts']}",
        f"- passes: {metrics['passes']}",
        f"- failures: {metrics['failures']}",
        f"- pass_rate: {metrics['pass_rate']:.4f}",
        f"- swarm_collapse_rate: {metrics['swarm_collapse_rate']:.4f}",
        f"- latency_p95_ms: {metrics['latency_ms']['p95']:.3f}",
        f"- proof_bytes_max: {metrics['proof_bytes_total']['max']:.0f}",
        f"- failure_reasons: {json.dumps(metrics['failure_reasons'], sort_keys=True)}",
        "",
        "Report zero observed unauthorized passes as an observation under this configuration,",
        "not as an impossibility claim.",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def process_resource_use() -> dict[str, float]:
    usage = resource.getrusage(resource.RUSAGE_SELF)
    raw_maxrss = float(usage.ru_maxrss)
    if platform.system() == "Darwin":
        memory_mb = raw_maxrss / (1024 * 1024)
    else:
        memory_mb = raw_maxrss / 1024
    return {
        "memory_mb_maxrss": memory_mb,
        "user_cpu_seconds": float(usage.ru_utime),
        "system_cpu_seconds": float(usage.ru_stime),
    }
