"""Protocol-agnostic fail-closed gate evaluation kit.

Drive any object implementing `Gate` through an honest round plus attacker-
capability profiles (real attacks expected to fail closed; positive controls
expected to release), and get a uniform report with Clopper-Pearson intervals and
a redaction scan. USAG and UCOG are the reference gates.
"""

from spatial_swarm.evalkit.gate import (
    STANDARD_CAPABILITIES,
    AttackerCapability,
    Gate,
    RoundOutcome,
)
from spatial_swarm.evalkit.gates import UCOGGate, USAGGate
from spatial_swarm.evalkit.runner import (
    CapabilityReport,
    EvalReport,
    evaluate_gate,
)

__all__ = [
    "AttackerCapability",
    "CapabilityReport",
    "EvalReport",
    "Gate",
    "RoundOutcome",
    "STANDARD_CAPABILITIES",
    "UCOGGate",
    "USAGGate",
    "evaluate_gate",
]
