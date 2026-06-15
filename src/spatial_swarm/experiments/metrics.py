"""Metrics aggregation from run results and JSONL events."""

from __future__ import annotations

import hashlib
import json
import math
import platform
import resource
import statistics
from pathlib import Path
from typing import Any

from spatial_swarm.experiments.stats import clopper_pearson
from spatial_swarm.protocol.verifier import VerificationResult


def summarize_results(results: list[VerificationResult], scenario: str) -> dict[str, Any]:
    attempts = len(results)
    passes = sum(1 for result in results if result.passed)
    failures = attempts - passes
    latencies = [result.latency_ms for result in results]
    proof_totals = [result.proof_bytes_total for result in results]
    failure_reasons: dict[str, int] = {}
    stage_distribution: dict[str, int] = {}
    packets_before_failure: list[float] = []
    signatures_verified: list[float] = []
    decryptions_performed: list[float] = []
    geometry_checks_performed: list[float] = []
    ejections = 0
    collapses = 0
    for result in results:
        if result.failure_reason:
            failure_reasons[result.failure_reason] = failure_reasons.get(result.failure_reason, 0) + 1
        failure_event = next((event for event in result.events if event.event_type == "proof_failed"), None)
        terminal_event = failure_event or next(
            (event for event in reversed(result.events) if event.event_type == "message_released"),
            None,
        )
        if terminal_event:
            if terminal_event.failure_stage:
                stage_distribution[terminal_event.failure_stage] = (
                    stage_distribution.get(terminal_event.failure_stage, 0) + 1
                )
            if terminal_event.packets_checked_before_failure is not None:
                packets_before_failure.append(float(terminal_event.packets_checked_before_failure))
            if terminal_event.signatures_verified is not None:
                signatures_verified.append(float(terminal_event.signatures_verified))
            if terminal_event.decryptions_performed is not None:
                decryptions_performed.append(float(terminal_event.decryptions_performed))
            if terminal_event.geometry_checks_performed is not None:
                geometry_checks_performed.append(float(terminal_event.geometry_checks_performed))
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
        "pass_rate_ci95": _proportion_ci(passes, attempts),
        "failure_rate": failures / attempts if attempts else 0.0,
        "ejections": ejections,
        "swarm_collapse_rate": collapses / attempts if attempts else 0.0,
        "failure_reasons": failure_reasons,
        "stage_distribution": stage_distribution,
        "packets_checked_before_failure": _latency_summary(packets_before_failure),
        "signatures_verified": _latency_summary(signatures_verified),
        "decryptions_performed": _latency_summary(decryptions_performed),
        "geometry_checks_performed": _latency_summary(geometry_checks_performed),
        "latency_ms": _latency_summary(latencies),
        "proof_bytes_total": _latency_summary(proof_totals),
    }


def _proportion_ci(successes: int, n: int) -> dict[str, float]:
    """Exact 95% Clopper-Pearson interval for the pass rate over `n` trials."""

    low, high = clopper_pearson(successes, n)
    return {"low": low, "high": high}


def _latency_summary(values: list[float]) -> dict[str, float]:
    if not values:
        return {"p50": 0.0, "p95": 0.0, "p99": 0.0, "max": 0.0}
    ordered = sorted(float(value) for value in values)
    return {
        "p50": statistics.median(ordered),
        "p95": _percentile(ordered, 0.95),
        "p99": _percentile(ordered, 0.99),
        "max": max(ordered),
    }


def _percentile(ordered: list[float], percentile: float) -> float:
    return ordered[min(len(ordered) - 1, math.ceil(percentile * len(ordered)) - 1)]


def read_events(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def write_metrics(path: Path, metrics: dict[str, Any]) -> None:
    path.write_text(json.dumps(metrics, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_metrics_and_digest(path: Path, metrics: dict[str, Any]) -> str:
    """Write metrics and a sibling `<name>.sha256` binding the file's bytes."""

    write_metrics(path, metrics)
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    path.with_name(path.name + ".sha256").write_text(digest + "\n", encoding="utf-8")
    return digest


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
        f"- stage_distribution: {json.dumps(metrics.get('stage_distribution', {}), sort_keys=True)}",
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
