"""Protocol-agnostic interface for a fail-closed message gate.

A gate releases an inter-agent message only when its release condition holds. The
eval kit drives any object implementing this interface through an honest round and
a set of attacker-capability profiles, and reports release rates with confidence
intervals plus a redaction scan. USAG and UCOG are the two reference gates
(`spatial_swarm.evalkit.gates`); a new gate is added by implementing `Gate`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Protocol, runtime_checkable


@dataclass(frozen=True)
class AttackerCapability:
    """What an attacker holds for one impersonation attempt against a gate."""

    key: str
    has_signing_authority: bool = False     # the target agent's signing key
    has_target_secret: bool = False         # the target agent's committed secret
    has_decryption_key: bool = False        # the gateway decryption key (host compromise)
    leaks_target_secret: bool = False       # the target secret leaked some other way
    is_positive_control: bool = False        # expected to RELEASE (proves the kit sees a break)


@dataclass(frozen=True)
class RoundOutcome:
    """The result of one gate round."""

    passed: bool                            # was the message released?
    failure_reason: Optional[str] = None
    failure_stage: Optional[str] = None
    secret_leaked: bool = False


# The standard capability set: three real attacks (must fail closed) and two
# positive controls (must release, so the kit can show it detects a real break).
STANDARD_CAPABILITIES: tuple[AttackerCapability, ...] = (
    AttackerCapability("no_keys_no_secret"),
    AttackerCapability("signing_key_only", has_signing_authority=True),
    AttackerCapability("secret_only", has_target_secret=True),
    AttackerCapability(
        "decryption_key_compromise",
        has_signing_authority=True,
        has_decryption_key=True,
        is_positive_control=True,
    ),
    AttackerCapability(
        "leaked_secret",
        has_signing_authority=True,
        leaks_target_secret=True,
        is_positive_control=True,
    ),
)


@runtime_checkable
class Gate(Protocol):
    """A fail-closed message gate the eval kit can drive."""

    name: str

    def honest_round(self, agent_count: int, fragment_size: int, seed: int) -> RoundOutcome:
        """Run a round where every agent behaves honestly (expected: released)."""

    def attack_round(
        self,
        agent_count: int,
        fragment_size: int,
        seed: int,
        capability: AttackerCapability,
    ) -> RoundOutcome:
        """Run a round where the target is impersonated with `capability`."""

    def artifact_text(self, agent_count: int, fragment_size: int, seed: int) -> str:
        """Return the gate's observable text output (packets/logs) for redaction scanning."""
