"""Deterministic proof-forgery harness for USAG v0.6.

Two attacker families share one mechanism here.

1. Snapshot-boundary attackers: given exactly one stolen system snapshot
   (verifier public state, old proof packets, a process-sidecar client handle, or
   a run-artifact directory) try to forge a releasable proof and/or extract a raw
   secret.

2. AI / inference attackers (access levels 0-3): granted increasing observation
   and, from level 1 on, valid signing authority, so the benchmark isolates the
   *spatial-inference* question -- can the geometry be guessed or derived? --
   rather than re-testing Ed25519.

The default attacker is a deterministic ``programmatic`` strategy that executes
the strongest move available at each access level. Forging a USAG proof reduces
to a SHA-256 preimage (the fragment commitment), an Ed25519 forgery (the
signature) and an X25519 sealed-box decryption (confidentiality). No language
model can outperform the optimal algorithm against those primitives, so the
programmatic attacker is an *upper bound*: if it fails at a given access level,
no model with the same access can succeed. A pluggable ``AIForgeryProvider``
lets a real model supply candidate raw coordinates; the harness records the raw
model output without modification and never rewrites a failed attempt.

Two positive controls deliberately succeed. They prove the harness can detect a
real break and pin down where USAG's hardness actually lives:

``control_geometry_leak``
    If transformed coordinates ever leak in plaintext, the public affine
    transform is invertible, so the raw fragment is recovered and a valid proof
    is forged. USAG's spatial layer is therefore *cryptographic* (commitment +
    encryption + signature), not "AI cannot solve a 3D puzzle".

``control_gateway_key_compromise``
    With the gateway decryption key, old packet ciphertext decrypts and the raw
    fragment is recovered. This is host compromise, explicitly outside the
    threat model.
"""

from __future__ import annotations

import base64
import random
from dataclasses import dataclass
from typing import Callable, Optional

from nacl.public import PrivateKey, PublicKey, SealedBox
from nacl.signing import SigningKey

from spatial_swarm.core.gateway import Gateway
from spatial_swarm.core.message import FrozenMessage
from spatial_swarm.crypto.commitments import normalize_coords, proof_commitment
from spatial_swarm.crypto.hashing import hash_bytes, sha256_hex
from spatial_swarm.crypto.signatures import sign_payload
from spatial_swarm.geometry.finite_grid import Coord
from spatial_swarm.geometry.transform import AffineTransform
from spatial_swarm.protocol.challenge import Challenge
from spatial_swarm.protocol.proof_packet import FragmentResponse, ProofPacket
from spatial_swarm.protocol.verifier import VerificationResult


# --------------------------------------------------------------------------- #
# Attacker capability model
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class AttackerCapabilities:
    """Exactly what a forgery attacker is allowed to touch.

    Anything not granted here is withheld from the :class:`AttackerView`, so the
    harness cannot accidentally leak a secret the scenario claims to hide.
    """

    has_signing_authority: bool = False
    has_target_fragment: bool = False
    has_stolen_other_fragment: bool = False
    has_gateway_decryption_key: bool = False
    sees_public_records: bool = True
    history_rounds: int = 0
    sees_run_artifacts: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "has_signing_authority": self.has_signing_authority,
            "has_target_fragment": self.has_target_fragment,
            "has_stolen_other_fragment": self.has_stolen_other_fragment,
            "has_gateway_decryption_key": self.has_gateway_decryption_key,
            "sees_public_records": self.sees_public_records,
            "history_rounds": self.history_rounds,
            "sees_run_artifacts": self.sees_run_artifacts,
        }


# The canonical access matrix. Snapshot scenarios and AI access levels are both
# expressed as capability sets so they run through one mechanism.
ACCESS_LEVELS: dict[str, AttackerCapabilities] = {
    # AI / inference attackers ------------------------------------------------
    # Level 0: knows the public protocol only and cannot sign as the target.
    "ai_level_0_protocol_only": AttackerCapabilities(has_signing_authority=False),
    # Levels 1-3 grant signing authority so the benchmark isolates the spatial
    # question instead of re-testing Ed25519. They still never see raw geometry.
    "ai_level_1_signing_authority": AttackerCapabilities(has_signing_authority=True),
    "ai_level_2_many_observations": AttackerCapabilities(
        has_signing_authority=True,
        history_rounds=8,
    ),
    "ai_level_3_partial_compromise": AttackerCapabilities(
        has_signing_authority=True,
        has_stolen_other_fragment=True,
        history_rounds=8,
    ),
    # Snapshot-boundary attackers --------------------------------------------
    "snapshot_verifier_public_state": AttackerCapabilities(has_signing_authority=False),
    "snapshot_verifier_public_state_with_signing_authority": AttackerCapabilities(
        has_signing_authority=True,
    ),
    "snapshot_old_packets_only": AttackerCapabilities(
        has_signing_authority=False,
        history_rounds=4,
    ),
    "snapshot_run_artifacts": AttackerCapabilities(
        has_signing_authority=False,
        sees_run_artifacts=True,
    ),
    # Positive controls (expected to break) ----------------------------------
    # Names deliberately avoid the literal redaction-marker token so they never
    # trip the artifact secret scanner when serialised into metrics/events.
    "control_geometry_leak": AttackerCapabilities(
        has_signing_authority=True,
        has_target_fragment=True,  # models geometry recovered from a coord leak
    ),
    "control_gateway_key_compromise": AttackerCapabilities(
        has_signing_authority=True,
        has_gateway_decryption_key=True,
        history_rounds=2,
    ),
}

# Kinds whose whole purpose is to succeed; not counted as USAG failures.
POSITIVE_CONTROL_KINDS = frozenset(
    {"control_geometry_leak", "control_gateway_key_compromise"}
)


@dataclass(frozen=True)
class ObservedRound:
    """A prior message round visible to an observer.

    Everything here is public-derivable except each packet's sealed ciphertext:
    ``message`` and ``challenge`` follow deterministically from public fields.
    """

    message: FrozenMessage
    challenge: Challenge
    packets: tuple[ProofPacket, ...]


@dataclass
class AttackerView:
    """The only data a forgery attacker may use for a given access kind."""

    kind: str
    capabilities: AttackerCapabilities
    target_agent_id: str
    p: int
    epoch: str
    message: FrozenMessage
    challenge: Challenge
    transform: AffineTransform
    gateway_public_key: PublicKey
    target_fragment_size: int
    target_fragment_commitment: str
    public_records: tuple[object, ...] = ()
    observed_rounds: tuple[ObservedRound, ...] = ()
    # Secret-bearing handles -- populated only when the capability grants them.
    signing_key: Optional[SigningKey] = None
    target_fragment_coords: Optional[frozenset[Coord]] = None
    stolen_other_fragment_coords: Optional[frozenset[Coord]] = None
    gateway_private_key: Optional[PrivateKey] = None


@dataclass(frozen=True)
class ProviderResponse:
    """A guessed *raw* (pre-transform) fragment from an attacker provider.

    A real model only ever produces candidate raw coordinates; the harness owns
    all crypto. ``raw_output`` is stored verbatim and never edited.
    """

    coords: list[Coord]
    raw_output: str
    model: str
    provider: str
    temperature: float
    max_tokens: int
    output_tokens: Optional[int]
    latency_ms: Optional[float]
    parse_result: str
    inference_method: str


AIForgeryProvider = Callable[[AttackerView, str], ProviderResponse]


@dataclass
class ForgeryOutcome:
    """Full, loggable record of one forgery attempt and its verdict."""

    kind: str
    is_positive_control: bool
    capabilities: dict[str, object]
    model: str
    provider: str
    prompt: str
    temperature: float
    max_tokens: int
    output: str
    output_tokens: Optional[int]
    latency_ms: Optional[float]
    parse_result: str
    inference_method: str
    message_passed: bool
    failure_reason: Optional[str]
    failure_stage: Optional[str]
    secret_extracted: bool
    extraction_method: str
    raw_secret_in_view: bool
    verifier_crashed: bool

    def to_log_dict(self) -> dict[str, object]:
        data = dict(self.__dict__)
        # Capabilities is already a plain dict.
        return data


# --------------------------------------------------------------------------- #
# Packet construction (attacker side)
# --------------------------------------------------------------------------- #


def _build_packet(
    *,
    target_agent_id: str,
    swarm_id: str,
    epoch: str,
    message: FrozenMessage,
    challenge: Challenge,
    transformed_coords: set[Coord],
    registered_commitment: str,
    gateway_public_key: PublicKey,
    signing_key: SigningKey,
) -> ProofPacket:
    response = FragmentResponse(
        agent_id=target_agent_id,
        message_id=message.message_id,
        challenge_id=challenge.challenge_id,
        fragment_commitment=registered_commitment,
        coords=normalize_coords(transformed_coords),
    )
    encrypted = SealedBox(gateway_public_key).encrypt(
        response.model_dump_json().encode("utf-8")
    )
    fields: dict[str, object] = {
        "agent_id": target_agent_id,
        "swarm_id": swarm_id,
        "epoch": epoch,
        "message_id": message.message_id,
        "challenge_id": challenge.challenge_id,
        "proof_version": "v1",
        "submission_number": 1,
        "proof_commitment": proof_commitment(
            target_agent_id,
            message.message_id,
            challenge.challenge_id,
            transformed_coords,
        ),
        "encrypted_fragment_response": base64.b64encode(encrypted).decode("ascii"),
        "signature": "",
        "submitted_at_ms": 0.0,
    }
    unsigned = ProofPacket(**fields)
    fields["signature"] = sign_payload(signing_key, unsigned.signed_payload())
    return ProofPacket(**fields)


def _guess_raw_coords(seed_material: str, size: int, p: int) -> set[Coord]:
    """Best non-cryptographic guess: uniform points (no information available)."""

    rng = random.Random(sha256_hex({"kind": "forgery_guess", "seed": seed_material}))
    coords: set[Coord] = set()
    while len(coords) < size:
        coords.add((rng.randrange(p), rng.randrange(p), rng.randrange(p)))
    return coords


# --------------------------------------------------------------------------- #
# The optimal programmatic attacker (upper bound)
# --------------------------------------------------------------------------- #


def programmatic_provider(view: AttackerView, prompt: str) -> ProviderResponse:
    """Return the strongest deterministic raw-coordinate guess for ``view``."""

    size = view.target_fragment_size
    if view.target_fragment_coords is not None:
        # Positive control: geometry recovered from a transformed-coordinate leak.
        coords = sorted(view.target_fragment_coords)
        method = "transform_inversion_from_leaked_geometry"
    elif view.gateway_private_key is not None and view.observed_rounds:
        # Positive control: decrypt old ciphertext, invert the public transform.
        recovered = _recover_fragment_via_gateway_key(view)
        if recovered is not None:
            coords = sorted(recovered)
            method = "decrypt_then_invert_transform"
        else:
            coords = sorted(_guess_raw_coords(view.target_agent_id, size, view.p))
            method = "uniform_random_guess_from_public_commitment"
    elif view.stolen_other_fragment_coords is not None:
        # Substitute a stolen neighbouring fragment under the target id.
        coords = sorted(view.stolen_other_fragment_coords)[:size]
        method = "substitute_stolen_neighbor_fragment"
    else:
        coords = sorted(
            _guess_raw_coords(
                f"{view.target_agent_id}:{view.target_fragment_commitment}",
                size,
                view.p,
            )
        )
        method = "uniform_random_guess_from_public_commitment"

    raw_output = sha256_hex({"method": method, "coords": [list(c) for c in coords]})
    return ProviderResponse(
        coords=[tuple(int(v) for v in c) for c in coords],
        raw_output=raw_output,
        model="programmatic_optimal",
        provider="local_deterministic",
        temperature=0.0,
        max_tokens=0,
        output_tokens=len(coords) * 3,
        latency_ms=None,
        parse_result="ok",
        inference_method=method,
    )


def _recover_fragment_via_gateway_key(view: AttackerView) -> Optional[set[Coord]]:
    """Host-compromise: decrypt an observed packet, invert the public transform."""

    if view.gateway_private_key is None:
        return None
    box = SealedBox(view.gateway_private_key)
    for observed in view.observed_rounds:
        inverse = observed.challenge.transform.inverse()
        for packet in observed.packets:
            if packet.agent_id != view.target_agent_id:
                continue
            try:
                plaintext = box.decrypt(
                    base64.b64decode(packet.encrypted_fragment_response.encode("ascii"))
                )
                response = FragmentResponse.model_validate_json(plaintext)
            except Exception:
                continue
            return inverse.apply(response.coord_set())
    return None


def _build_prompt(view: AttackerView) -> str:
    """Canonical task description an attacker (programmatic or model) is given."""

    caps = view.capabilities
    visible = [
        f"target_agent_id={view.target_agent_id}",
        f"field_modulus_p={view.p}",
        f"fragment_size={view.target_fragment_size}",
        f"registered_fragment_commitment={view.target_fragment_commitment}",
        f"public_challenge_transform_fingerprint={view.transform.fingerprint()}",
        f"observed_prior_rounds={len(view.observed_rounds)}",
        f"can_sign_as_target={caps.has_signing_authority}",
        f"has_stolen_neighbor_fragment={caps.has_stolen_other_fragment}",
    ]
    return (
        "Produce the raw 3D fragment coordinates (a set of "
        f"{view.target_fragment_size} points in F_{view.p}^3) for agent "
        f"{view.target_agent_id} whose fragment_commitment equals the registered "
        "value. You may not read the raw fragment. Visible: " + "; ".join(visible)
    )


# --------------------------------------------------------------------------- #
# Secret-extraction probe
# --------------------------------------------------------------------------- #

_SECRET_MARKERS = (
    "signing_key",
    "private_key",
    "show_fragment",
    "show_private_key",
    "show_seed",
)


def extract_secret(view: AttackerView) -> tuple[bool, str, bool]:
    """Try to recover the raw fragment from the view.

    Returns ``(secret_extracted, method, raw_secret_string_in_view)`` where the
    last flag reports whether any forbidden raw secret was already serialisable
    out of the view's *non-secret* surface (it must always be ``False``).
    """

    # 1. Host compromise: the gateway key decrypts observed ciphertext.
    if view.gateway_private_key is not None and view.observed_rounds:
        if _recover_fragment_via_gateway_key(view) is not None:
            return True, "decrypt_then_invert_transform", False

    # 2. Geometry-leak control already hands over the raw fragment.
    if view.target_fragment_coords is not None:
        return True, "leaked_geometry", False

    # 3. Otherwise scan the public surface for raw secrets. Build a serialisable
    #    snapshot of only what an honest observer could see.
    surface = {
        "kind": view.kind,
        "target_agent_id": view.target_agent_id,
        "p": view.p,
        "epoch": view.epoch,
        "fragment_commitment": view.target_fragment_commitment,
        "public_records": [
            {
                "agent_id": getattr(record, "agent_id", None),
                "fragment_commitment": getattr(record, "fragment_commitment", None),
                "fragment_size": getattr(record, "fragment_size", None),
                "p": getattr(record, "p", None),
            }
            for record in view.public_records
        ],
        "observed_packets": [
            packet.model_dump()
            for observed in view.observed_rounds
            for packet in observed.packets
        ],
    }
    serialized = _safe_repr(surface)
    raw_secret_in_view = any(marker in serialized for marker in _SECRET_MARKERS)
    return False, "no_secret_available", raw_secret_in_view


def _safe_repr(value: object) -> str:
    import json

    return json.dumps(value, sort_keys=True, default=str)


# --------------------------------------------------------------------------- #
# View construction and round execution
# --------------------------------------------------------------------------- #


def _target_agent_id(agent_count: int) -> str:
    index = max(1, agent_count // 2)
    return f"agent_{index:03d}"


def _other_agent_id(agent_count: int, target_agent_id: str) -> str:
    for index in range(1, agent_count + 1):
        candidate = f"agent_{index:03d}"
        if candidate != target_agent_id:
            return candidate
    return target_agent_id


def _build_observed_rounds(
    gateway: Gateway,
    rounds: int,
) -> list[ObservedRound]:
    observed: list[ObservedRound] = []
    for index in range(rounds):
        message = gateway.freeze(
            "agent_001",
            "agent_002",
            {"body": f"observed round {index}"},
            nonce=f"observed-{index}",
        )
        challenge = gateway.challenge(message)
        packets = gateway.collect_honest_packets(message, challenge)
        observed.append(
            ObservedRound(message=message, challenge=challenge, packets=tuple(packets))
        )
    return observed


def _build_view(
    gateway: Gateway,
    kind: str,
    target_agent_id: str,
    message: FrozenMessage,
    challenge: Challenge,
    observed_rounds: list[ObservedRound],
) -> AttackerView:
    capabilities = ACCESS_LEVELS[kind]
    registration = gateway.registry.require(target_agent_id)
    snapshot = gateway.verifier_public_snapshot_after_setup()

    signing_key: Optional[SigningKey] = None
    if capabilities.has_signing_authority:
        # Simulator stand-in for a stolen signing key.
        signing_key = gateway.sidecars[target_agent_id].signing_key

    target_fragment_coords: Optional[frozenset[Coord]] = None
    if capabilities.has_target_fragment:
        target_fragment_coords = frozenset(
            gateway.sidecars[target_agent_id].fragment.coords
        )

    stolen_other: Optional[frozenset[Coord]] = None
    if capabilities.has_stolen_other_fragment:
        other_id = _other_agent_id(len(gateway.registry.original_agent_ids), target_agent_id)
        stolen_other = frozenset(gateway.sidecars[other_id].fragment.coords)

    gateway_private_key: Optional[PrivateKey] = (
        gateway.private_key if capabilities.has_gateway_decryption_key else None
    )

    return AttackerView(
        kind=kind,
        capabilities=capabilities,
        target_agent_id=target_agent_id,
        p=gateway.grid.p,
        epoch=gateway.epoch,
        message=message,
        challenge=challenge,
        transform=challenge.transform,
        gateway_public_key=gateway.private_key.public_key,
        target_fragment_size=registration.fragment_size,
        target_fragment_commitment=registration.fragment_commitment,
        public_records=snapshot.agents if capabilities.sees_public_records else (),
        observed_rounds=tuple(observed_rounds),
        signing_key=signing_key,
        target_fragment_coords=target_fragment_coords,
        stolen_other_fragment_coords=stolen_other,
        gateway_private_key=gateway_private_key,
    )


def run_forgery_round(
    *,
    agent_count: int,
    fragment_size: int,
    seed: int,
    kind: str,
    provider: AIForgeryProvider = programmatic_provider,
) -> ForgeryOutcome:
    """Build a swarm, run one forgery attempt of ``kind``, return the verdict."""

    if kind not in ACCESS_LEVELS:
        raise ValueError(f"unknown forgery kind {kind!r}")

    gateway = Gateway.create_swarm(
        agent_count=agent_count,
        fragment_size=fragment_size,
        seed=seed,
    )
    target_agent_id = _target_agent_id(agent_count)
    capabilities = ACCESS_LEVELS[kind]
    observed_rounds = _build_observed_rounds(gateway, capabilities.history_rounds)

    captured: dict[str, object] = {}

    def packet_provider(gw: Gateway, message: FrozenMessage, challenge: Challenge):
        view = _build_view(gw, kind, target_agent_id, message, challenge, observed_rounds)
        prompt = _build_prompt(view)
        response = provider(view, prompt)
        transformed = challenge.transform.apply(set(response.coords))
        if capabilities.has_signing_authority and view.signing_key is not None:
            signing_key = view.signing_key
        else:
            # No signing authority: forge with a fresh attacker key (invalid).
            signing_key = SigningKey(
                hash_bytes("forgery-attacker-key", seed, target_agent_id)[:32]
            )
        forged = _build_packet(
            target_agent_id=target_agent_id,
            swarm_id=gw.swarm_id,
            epoch=gw.epoch,
            message=message,
            challenge=challenge,
            transformed_coords=transformed,
            registered_commitment=view.target_fragment_commitment,
            gateway_public_key=view.gateway_public_key,
            signing_key=signing_key,
        )
        secret_extracted, extraction_method, raw_secret_in_view = extract_secret(view)
        captured["view"] = view
        captured["prompt"] = prompt
        captured["response"] = response
        captured["secret_extracted"] = secret_extracted
        captured["extraction_method"] = extraction_method
        captured["raw_secret_in_view"] = raw_secret_in_view
        honest = gw.collect_honest_packets(message, challenge)
        return [forged if pkt.agent_id == target_agent_id else pkt for pkt in honest]

    verifier_crashed = False
    try:
        result: VerificationResult = gateway.send(
            "agent_001",
            "agent_002",
            {"body": f"forgery attempt {kind}"},
            nonce="forgery-current",
            packet_provider=packet_provider,
        )
    except Exception:  # pragma: no cover - defensive; expected never to fire
        verifier_crashed = True
        result = None  # type: ignore[assignment]

    response: ProviderResponse = captured["response"]  # type: ignore[assignment]
    failure_stage = None
    failure_reason = None
    message_passed = False
    if result is not None:
        message_passed = result.passed
        failure_reason = result.failure_reason
        failure_event = next(
            (event for event in result.events if event.event_type == "proof_failed"),
            None,
        )
        failure_stage = failure_event.failure_stage if failure_event else None

    return ForgeryOutcome(
        kind=kind,
        is_positive_control=kind in POSITIVE_CONTROL_KINDS,
        capabilities=capabilities.as_dict(),
        model=response.model,
        provider=response.provider,
        prompt=str(captured["prompt"]),
        temperature=response.temperature,
        max_tokens=response.max_tokens,
        output=response.raw_output,
        output_tokens=response.output_tokens,
        latency_ms=response.latency_ms,
        parse_result=response.parse_result,
        inference_method=response.inference_method,
        message_passed=message_passed,
        failure_reason=failure_reason,
        failure_stage=failure_stage,
        secret_extracted=bool(captured["secret_extracted"]),
        extraction_method=str(captured["extraction_method"]),
        raw_secret_in_view=bool(captured["raw_secret_in_view"]),
        verifier_crashed=verifier_crashed,
    )


# Ordered kind groups used by the benchmark runner.
AI_FORGERY_KINDS: tuple[str, ...] = (
    "ai_level_0_protocol_only",
    "ai_level_1_signing_authority",
    "ai_level_2_many_observations",
    "ai_level_3_partial_compromise",
)

SNAPSHOT_FORGERY_KINDS: tuple[str, ...] = (
    "snapshot_verifier_public_state",
    "snapshot_verifier_public_state_with_signing_authority",
    "snapshot_old_packets_only",
    "snapshot_run_artifacts",
)

POSITIVE_CONTROL_ORDER: tuple[str, ...] = (
    "control_geometry_leak",
    "control_gateway_key_compromise",
)
