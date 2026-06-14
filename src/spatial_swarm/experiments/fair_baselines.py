"""Fair, fully-executed, UNANIMOUS baseline gates for the honest reframe.

The existing baselines (``baselines.py``) decide pass/fail from a hard-coded
``ScenarioProfile`` lookup, and the strongest one signs only message metadata --
it never forces an agent to OPEN a per-agent registered secret. That makes the
"spatial layer adds protection" headline a comparison against a gate that checks
the wrong thing.

This module adds the missing control: a real **Unanimous Commitment-Opening Gate
(UCOG)** that executes actual cryptography and mirrors USAG's verifier structure
(registration -> message binding -> signature -> opening -> all-N participation ->
disjointness), differing from USAG in exactly one way -- no geometry, no affine
transform, no tiling. Every agent opens a per-agent committed secret (random
bytes), message-bound and signed.

All three gates (unanimous metadata-signature, UCOG, full USAG) are run end-to-end
against the SAME attacker, expressed in each gate's own packet format from one
shared ``ScenarioSpec``. The keystone question: does USAG's geometry catch any
attack that the non-geometric unanimous gate misses?

NOTE on scope (fairness): the matrix deliberately includes the multi-agent /
assembly class (partial_swarm, missing, duplicate, correct_geometry_wrong_agent_id)
-- the only scenarios where a unanimous gate could differ from a single-agent one
-- precisely so the comparison can FALSIFY the headline if geometry adds anything.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass

from nacl.public import PublicKey, SealedBox
from nacl.signing import SigningKey

from spatial_swarm.core.gateway import Gateway
from spatial_swarm.core.message import FrozenMessage
from spatial_swarm.crypto.hashing import hash_bytes, sha256_hex
from spatial_swarm.crypto.signatures import sign_payload, verify_payload


# --------------------------------------------------------------------------- #
# UCOG secret model: a per-agent committed secret with NO geometry.
# --------------------------------------------------------------------------- #


def ucog_secret(seed: int, agent_id: str) -> bytes:
    """A 32-byte per-agent secret -- the non-geometric analog of a fragment."""

    return hash_bytes("ucog-secret", seed, agent_id)[:32]


def ucog_commitment(agent_id: str, secret: bytes) -> str:
    """SHA-256 commitment the registry stores instead of a fragment_commitment."""

    return sha256_hex(
        {
            "kind": "ucog_commitment",
            "agent_id": agent_id,
            "secret": base64.b64encode(secret).decode("ascii"),
        }
    )


# --------------------------------------------------------------------------- #
# One shared scenario spec, applied in each gate's own packet format.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ScenarioSpec:
    """How the attacker perturbs the swarm's proof set (gate-agnostic)."""

    honest: bool = False
    target_has_signing_key: bool = True      # holds the target's Ed25519 key
    target_has_secret: bool = True           # knows the target's committed secret
    target_fresh: bool = True                # binds proof to the CURRENT message
    target_wrong_internal_id: bool = False   # opens another agent's secret under target id
    target_unregistered: bool = False        # target replaced by an unregistered id
    drop_target: bool = False                # target omitted (partial / missing swarm)
    duplicate_first: bool = False            # an extra duplicate of agent_001


# Canonical USAG attack scenarios -> capability/perturbation specs. Unknown
# scenarios raise (no silent fallthrough), so a new scenario cannot be silently
# mis-modeled as "wrong secret".
SCENARIO_SPECS: dict[str, ScenarioSpec] = {
    "honest": ScenarioSpec(honest=True),
    "fake_agent": ScenarioSpec(target_has_signing_key=False, target_has_secret=False),
    "unregistered_fake_agent": ScenarioSpec(target_unregistered=True),
    "replay": ScenarioSpec(target_fresh=False),
    "wrong_message": ScenarioSpec(target_fresh=False),
    "stolen_fragment_only": ScenarioSpec(target_has_signing_key=False, target_has_secret=True),
    # The four "USAG beats signatures" scenarios: valid signing key, NO secret.
    "valid_signature_wrong_geometry": ScenarioSpec(target_has_secret=False),
    "valid_signature_wrong_transform": ScenarioSpec(target_has_secret=False),
    "stolen_signing_authority_only": ScenarioSpec(target_has_secret=False),
    "verifier_snapshot_forgery": ScenarioSpec(target_has_secret=False),
    # Multi-agent / assembly class: the scenarios a unanimous gate could fail on.
    "correct_geometry_wrong_agent_id": ScenarioSpec(target_wrong_internal_id=True),
    "duplicate": ScenarioSpec(duplicate_first=True),
    "partial_swarm": ScenarioSpec(drop_target=True),
    "stolen_piece": ScenarioSpec(drop_target=True),
    "all_but_one_valid_spatial_piece": ScenarioSpec(drop_target=True),
    "missing": ScenarioSpec(drop_target=True),
}


def spec_for(scenario: str) -> ScenarioSpec:
    if scenario not in SCENARIO_SPECS:
        raise ValueError(f"no fair-baseline spec for scenario {scenario!r}")
    return SCENARIO_SPECS[scenario]


@dataclass(frozen=True)
class GateResult:
    gate: str
    scenario: str
    passed: bool
    failure_reason: str
    unauthorized: bool


@dataclass
class SwarmContext:
    """Real key material shared by the gates so geometry is the only variable."""

    gateway: Gateway
    seed: int
    agent_ids: tuple[str, ...]
    target_agent_id: str
    other_agent_id: str
    gateway_public_key: PublicKey
    epoch: str

    @classmethod
    def build(cls, agent_count: int, fragment_size: int, seed: int) -> "SwarmContext":
        gateway = Gateway.create_swarm(
            agent_count=agent_count, fragment_size=fragment_size, seed=seed
        )
        ids = gateway.registry.original_agent_ids
        target = ids[max(0, len(ids) // 2 - 1)]
        other = next(a for a in ids if a != target)
        return cls(
            gateway=gateway,
            seed=seed,
            agent_ids=ids,
            target_agent_id=target,
            other_agent_id=other,
            gateway_public_key=gateway.private_key.public_key,
            epoch=gateway.epoch,
        )

    def current_message(self) -> FrozenMessage:
        return self.gateway.freeze(
            "agent_001", "agent_002", {"body": "fair-baseline"}, nonce="current"
        )

    def old_message(self) -> FrozenMessage:
        return self.gateway.freeze(
            "agent_001", "agent_002", {"body": "fair-baseline"}, nonce="old"
        )

    def real_key(self, agent_id: str) -> SigningKey:
        return self.gateway.sidecars[agent_id].signing_key

    def attacker_key(self) -> SigningKey:
        return SigningKey(hash_bytes("fair-attacker-key", self.seed, self.target_agent_id)[:32])


# --------------------------------------------------------------------------- #
# Gate 1: unanimous signature over message metadata (real, executed). Requires
# every agent to sign, but never opens a per-agent secret.
# --------------------------------------------------------------------------- #


def _metadata_payload(message: FrozenMessage) -> dict[str, str]:
    return {
        "message_id": message.message_id,
        "sender_id": message.sender_id,
        "receiver_id": message.receiver_id,
        "epoch": message.epoch,
        "gate": "unanimous_signature",
    }


def _metasig_packet(agent_id: str, message_id: str, signing_key: SigningKey, signed: FrozenMessage) -> dict:
    return {
        "agent_id": agent_id,
        "message_id": message_id,
        "signature": sign_payload(signing_key, _metadata_payload(signed)),
    }


def build_metasig_packets(ctx: SwarmContext, spec: ScenarioSpec) -> list[dict]:
    current, old = ctx.current_message(), ctx.old_message()
    packets: list[dict] = []
    for agent_id in ctx.agent_ids:
        if agent_id == ctx.target_agent_id and not spec.honest:
            if spec.drop_target:
                continue
            if spec.target_unregistered:
                packets.append(
                    _metasig_packet("agent_999", current.message_id, ctx.attacker_key(), current)
                )
                continue
            signed = current if spec.target_fresh else old
            key = ctx.real_key(agent_id) if spec.target_has_signing_key else ctx.attacker_key()
            bound_id = current.message_id if spec.target_fresh else old.message_id
            packets.append(_metasig_packet(agent_id, bound_id, key, signed))
        else:
            packets.append(_metasig_packet(agent_id, current.message_id, ctx.real_key(agent_id), current))
    if spec.duplicate_first and packets:
        packets.insert(0, packets[0])
    return packets


def metasig_verify(ctx: SwarmContext, packets: list[dict]) -> tuple[bool, str]:
    current = ctx.current_message()
    seen: set[str] = set()
    for pkt in packets:
        agent_id = pkt["agent_id"]
        registration = ctx.gateway.registry.get(agent_id)
        if registration is None:
            return False, "unregistered_agent"
        if pkt["message_id"] != current.message_id:
            return False, "wrong_message_hash"
        if not verify_payload(registration.verify_key, _metadata_payload(current), pkt["signature"]):
            return False, "wrong_signature"
        seen.add(agent_id)
    missing = [a for a in ctx.agent_ids if a not in seen]
    if missing:
        return False, "missing_packet"
    return True, "all_registered_agents_signed"


def gate_unanimous_signature(ctx: SwarmContext, scenario: str) -> GateResult:
    spec = spec_for(scenario)
    passed, reason = metasig_verify(ctx, build_metasig_packets(ctx, spec))
    return GateResult("unanimous_signature_metadata", scenario, passed, reason, scenario != "honest")


# --------------------------------------------------------------------------- #
# Gate 2: Unanimous Commitment-Opening Gate (UCOG) -- the fair baseline.
# Same keys, encryption and message binding as USAG; NO geometry. Mirrors the
# USAG verifier's structure and check order, with the geometry inversion replaced
# by a plain SHA-256 commitment opening of a per-agent secret.
# --------------------------------------------------------------------------- #


def _ucog_signed_payload(agent_id: str, message: FrozenMessage) -> dict[str, str]:
    return {"agent_id": agent_id, "message_id": message.message_id, "epoch": message.epoch, "gate": "ucog"}


def _ucog_packet(
    ctx: SwarmContext,
    outer_agent_id: str,
    inner_agent_id: str,
    secret: bytes,
    signed_message: FrozenMessage,
    signing_key: SigningKey,
) -> dict:
    opening = {
        "agent_id": inner_agent_id,
        "message_id": signed_message.message_id,
        "secret": base64.b64encode(secret).decode("ascii"),
    }
    encrypted = SealedBox(ctx.gateway_public_key).encrypt(
        base64.b64encode(json.dumps(opening, sort_keys=True).encode("utf-8"))
    )
    return {
        "agent_id": outer_agent_id,
        "epoch": ctx.epoch,
        "message_id": signed_message.message_id,
        "submission_number": 1,
        "encrypted_opening": base64.b64encode(encrypted).decode("ascii"),
        "signature": sign_payload(signing_key, _ucog_signed_payload(outer_agent_id, signed_message)),
    }


def build_ucog_packets(ctx: SwarmContext, spec: ScenarioSpec) -> list[dict]:
    current, old = ctx.current_message(), ctx.old_message()
    packets: list[dict] = []
    for agent_id in ctx.agent_ids:
        honest = _ucog_packet(
            ctx, agent_id, agent_id, ucog_secret(ctx.seed, agent_id), current, ctx.real_key(agent_id)
        )
        if agent_id != ctx.target_agent_id or spec.honest:
            packets.append(honest)
            continue
        if spec.drop_target:
            continue
        if spec.target_unregistered:
            packets.append(
                _ucog_packet(
                    ctx, "agent_999", "agent_999", ucog_secret(ctx.seed, "agent_999"),
                    current, ctx.attacker_key()
                )
            )
            continue
        signed = current if spec.target_fresh else old
        key = ctx.real_key(agent_id) if spec.target_has_signing_key else ctx.attacker_key()
        if spec.target_wrong_internal_id:
            inner, secret = ctx.other_agent_id, ucog_secret(ctx.seed, ctx.other_agent_id)
        elif spec.target_has_secret:
            inner, secret = agent_id, ucog_secret(ctx.seed, agent_id)
        else:
            inner, secret = agent_id, ucog_secret(ctx.seed, ctx.other_agent_id)  # wrong secret
        packets.append(_ucog_packet(ctx, agent_id, inner, secret, signed, key))
    if spec.duplicate_first and packets:
        packets.insert(0, packets[0])
    return packets


def ucog_verify(ctx: SwarmContext, packets: list[dict]) -> tuple[bool, str]:
    current = ctx.current_message()
    box = SealedBox(ctx.gateway.private_key)
    seen: set[str] = set()
    opened_secrets: list[str] = []
    for pkt in packets:
        agent_id = pkt["agent_id"]
        registration = ctx.gateway.registry.get(agent_id)
        if registration is None:
            return False, "unregistered_agent"
        if pkt["epoch"] != ctx.epoch:
            return False, "wrong_epoch"
        if pkt["message_id"] != current.message_id:
            return False, "wrong_message_hash"
        if pkt["submission_number"] != 1:
            return False, "invalid_submission_number"
        if agent_id in seen:
            return False, "duplicate_submission"
        seen.add(agent_id)
        if not verify_payload(
            registration.verify_key, _ucog_signed_payload(agent_id, current), pkt["signature"]
        ):
            return False, "wrong_signature"
        try:
            plaintext = box.decrypt(base64.b64decode(pkt["encrypted_opening"].encode("ascii")))
            opening = json.loads(base64.b64decode(plaintext).decode("utf-8"))
            secret = base64.b64decode(opening["secret"].encode("ascii"))
        except Exception:
            return False, "opening_decrypt_failed"
        if opening["agent_id"] != agent_id or opening["message_id"] != current.message_id:
            return False, "response_binding_failed"
        registered = ucog_commitment(agent_id, ucog_secret(ctx.seed, agent_id))
        if ucog_commitment(agent_id, secret) != registered:
            return False, "commitment_opening_failed"
        opened_secrets.append(opening["secret"])
    missing = [a for a in ctx.agent_ids if a not in seen]
    if missing:
        return False, "missing_packet"
    if len(set(opened_secrets)) != len(opened_secrets):  # disjointness analog (redundant, like USAG's)
        return False, "assembly_failed"
    return True, "all_agents_opened"


def gate_unanimous_commitment_opening(ctx: SwarmContext, scenario: str) -> GateResult:
    spec = spec_for(scenario)
    passed, reason = ucog_verify(ctx, build_ucog_packets(ctx, spec))
    return GateResult("unanimous_commitment_opening", scenario, passed, reason, scenario != "honest")


# --------------------------------------------------------------------------- #
# Gate 3: full USAG, via the real runner scenario (the actual pipeline).
# --------------------------------------------------------------------------- #


def gate_usag(ctx: SwarmContext, scenario: str) -> GateResult:
    from spatial_swarm.experiments.runner import SCENARIOS

    runner = SCENARIOS.get(scenario)
    if runner is None:
        raise ValueError(f"no USAG runner for scenario {scenario!r}")
    result = runner(
        len(ctx.agent_ids),
        ctx.gateway.sidecars[ctx.target_agent_id].fragment.size,
        ctx.seed,
        None,
    )
    return GateResult(
        "usag_full", scenario, result.passed, result.failure_reason or "message_released",
        scenario != "honest",
    )


GATES = {
    "unanimous_signature_metadata": gate_unanimous_signature,
    "unanimous_commitment_opening": gate_unanimous_commitment_opening,
    "usag_full": gate_usag,
}

# Keystone scenario set: honest + signature-class attacks + the multi-agent /
# assembly class (the only scenarios that could distinguish a unanimous gate from
# a single-agent one, and so the only ones that could falsify the headline).
KEYSTONE_SCENARIOS = (
    "honest",
    "fake_agent",
    "unregistered_fake_agent",
    "replay",
    "stolen_fragment_only",
    "valid_signature_wrong_geometry",
    "valid_signature_wrong_transform",
    "stolen_signing_authority_only",
    "verifier_snapshot_forgery",
    "correct_geometry_wrong_agent_id",
    "duplicate",
    "partial_swarm",
    "missing",
)


def run_fair_baseline_matrix(
    agent_count: int = 8,
    fragment_size: int = 16,
    seed: int = 1337,
    scenarios: tuple[str, ...] = KEYSTONE_SCENARIOS,
) -> dict[str, object]:
    """Run every gate against every scenario, fully executed, adversary-uniform."""

    rows: dict[str, dict[str, GateResult]] = {}
    for scenario in scenarios:
        ctx = SwarmContext.build(agent_count, fragment_size, seed)
        rows[scenario] = {name: fn(ctx, scenario) for name, fn in GATES.items()}

    ucog_matches_usag = all(
        rows[s]["unanimous_commitment_opening"].passed == rows[s]["usag_full"].passed
        for s in scenarios
    )
    # Scenarios USAG catches that the metadata-signature gate does NOT.
    usag_beats_signature = [
        s for s in scenarios
        if rows[s]["unanimous_signature_metadata"].passed and not rows[s]["usag_full"].passed
    ]
    # Of those, which the non-geometric UCOG ALSO catches.
    ucog_also_catches = [
        s for s in usag_beats_signature if not rows[s]["unanimous_commitment_opening"].passed
    ]
    return {
        "scenarios": list(scenarios),
        "gates": list(GATES),
        "matrix": {
            s: {g: {"passed": r.passed, "reason": r.failure_reason} for g, r in row.items()}
            for s, row in rows.items()
        },
        "ucog_matches_usag_on_all_scenarios": ucog_matches_usag,
        "scenarios_where_signature_gate_is_beaten": usag_beats_signature,
        "scenarios_where_ucog_also_catches": ucog_also_catches,
        "geometry_marginal_advantage_count": len(usag_beats_signature) - len(ucog_also_catches),
    }
