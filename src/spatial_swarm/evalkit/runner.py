"""Generic fail-closed evaluation over any Gate.

`evaluate_gate` runs an honest round and each attacker-capability profile over a
set of seeds, and reports release rates with exact Clopper-Pearson intervals plus
a redaction scan of the gate's observable output. The report is gate-agnostic, so
USAG, UCOG, or a user-supplied gate produce the same shape of result.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Optional, Sequence

from spatial_swarm.evalkit.gate import STANDARD_CAPABILITIES, AttackerCapability, Gate
from spatial_swarm.experiments.redaction import SECRET_MARKERS, scan_text
from spatial_swarm.experiments.stats import clopper_pearson


def _ci(successes: int, n: int) -> dict[str, float]:
    low, high = clopper_pearson(successes, n)
    return {"low": low, "high": high}


@dataclass
class CapabilityReport:
    key: str
    is_positive_control: bool
    trials: int
    unauthorized_releases: int
    release_rate: float
    release_rate_ci95: dict[str, float]
    secret_leaks: int
    failure_reasons: dict[str, int]
    failure_stages: dict[str, int]


@dataclass
class EvalReport:
    gate_name: str
    trials: int
    honest_releases: int
    honest_release_rate: float
    honest_release_ci95: dict[str, float]
    capabilities: dict[str, CapabilityReport] = field(default_factory=dict)
    redaction_clean: bool = True
    redaction_hits: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "gate_name": self.gate_name,
            "trials": self.trials,
            "honest_releases": self.honest_releases,
            "honest_release_rate": self.honest_release_rate,
            "honest_release_ci95": self.honest_release_ci95,
            "capabilities": {k: vars(v) for k, v in self.capabilities.items()},
            "redaction_clean": self.redaction_clean,
            "redaction_hits": self.redaction_hits,
        }

    def render(self) -> str:
        lines = [
            f"Gate: {self.gate_name}  (trials={self.trials})",
            f"  honest releases: {self.honest_releases}/{self.trials} "
            f"[{self.honest_release_ci95['low']:.4f}, {self.honest_release_ci95['high']:.4f}]",
            "  attacker capabilities (unauthorized releases / trials):",
        ]
        for cap in self.capabilities.values():
            tag = " [positive control: expected to release]" if cap.is_positive_control else ""
            ci = cap.release_rate_ci95
            lines.append(
                f"    {cap.key:28s} {cap.unauthorized_releases:>3d}/{cap.trials:<3d} "
                f"[{ci['low']:.4f}, {ci['high']:.4f}] "
                f"leaks={cap.secret_leaks} reasons={cap.failure_reasons}{tag}"
            )
        lines.append(f"  redaction clean: {self.redaction_clean} hits={self.redaction_hits}")
        return "\n".join(lines)


def evaluate_gate(
    gate: Gate,
    *,
    agent_count: int = 4,
    fragment_size: int = 8,
    seeds: Optional[Sequence[int]] = None,
    capabilities: Sequence[AttackerCapability] = STANDARD_CAPABILITIES,
    redaction_sample: int = 3,
) -> EvalReport:
    seed_list = list(seeds) if seeds is not None else list(range(2000, 2020))
    n = len(seed_list)

    honest = [gate.honest_round(agent_count, fragment_size, s) for s in seed_list]
    honest_releases = sum(1 for o in honest if o.passed)

    cap_reports: dict[str, CapabilityReport] = {}
    for cap in capabilities:
        outcomes = [gate.attack_round(agent_count, fragment_size, s, cap) for s in seed_list]
        releases = sum(1 for o in outcomes if o.passed)
        reasons = Counter(o.failure_reason for o in outcomes if o.failure_reason)
        stages = Counter(o.failure_stage for o in outcomes if o.failure_stage)
        cap_reports[cap.key] = CapabilityReport(
            key=cap.key,
            is_positive_control=cap.is_positive_control,
            trials=n,
            unauthorized_releases=releases,
            release_rate=releases / n if n else 0.0,
            release_rate_ci95=_ci(releases, n),
            secret_leaks=sum(1 for o in outcomes if o.secret_leaked),
            failure_reasons=dict(reasons),
            failure_stages=dict(stages),
        )

    text = "\n".join(
        gate.artifact_text(agent_count, fragment_size, s) for s in seed_list[:redaction_sample]
    )
    hits = sorted(set(scan_text(text, SECRET_MARKERS)))

    return EvalReport(
        gate_name=gate.name,
        trials=n,
        honest_releases=honest_releases,
        honest_release_rate=honest_releases / n if n else 0.0,
        honest_release_ci95=_ci(honest_releases, n),
        capabilities=cap_reports,
        redaction_clean=not hits,
        redaction_hits=hits,
    )
