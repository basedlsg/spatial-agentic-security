"""Simple baseline comparisons for reviewer-facing experiments."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from nacl.signing import SigningKey

from spatial_swarm.core.gateway import Gateway
from spatial_swarm.core.message import freeze_message
from spatial_swarm.crypto.hashing import hash_bytes
from spatial_swarm.crypto.signatures import sign_payload, verify_payload


@dataclass(frozen=True)
class BaselineResult:
    name: str
    passed: bool
    reason: str


def direct_communication(sender_id: str, receiver_id: str, content: Any) -> BaselineResult:
    return BaselineResult(
        name="direct_communication",
        passed=True,
        reason="no membership gate exists",
    )


def central_gateway_only(gateway: Gateway, sender_id: str, receiver_id: str, content: Any) -> BaselineResult:
    if sender_id not in gateway.registry.original_agent_ids:
        return BaselineResult("central_gateway_only", False, "unregistered_sender")
    return BaselineResult("central_gateway_only", True, "registered_sender")


def signature_only_sender(
    gateway: Gateway,
    sender_id: str,
    receiver_id: str,
    content: Any,
    fake: bool = False,
) -> BaselineResult:
    message = freeze_message(sender_id, receiver_id, gateway.epoch, content)
    registration = gateway.registry.get(sender_id)
    if registration is None:
        return BaselineResult("signature_only_sender", False, "unregistered_sender")
    signing_key = (
        SigningKey(hash_bytes("baseline-fake-signing-key", sender_id)[:32])
        if fake
        else gateway.sidecars[sender_id].signing_key
    )
    payload = {"message_id": message.message_id, "sender_id": sender_id}
    signature = sign_payload(signing_key, payload)
    passed = verify_payload(registration.verify_key, payload, signature)
    return BaselineResult(
        "signature_only_sender",
        passed,
        "valid_sender_signature" if passed else "wrong_signature",
    )


def unanimous_signature(gateway: Gateway, sender_id: str, receiver_id: str, content: Any) -> BaselineResult:
    message = freeze_message(sender_id, receiver_id, gateway.epoch, content)
    payload = {"message_id": message.message_id, "sender_id": sender_id, "receiver_id": receiver_id}
    for agent_id in gateway.registry.original_agent_ids:
        signature = sign_payload(gateway.sidecars[agent_id].signing_key, payload)
        if not verify_payload(gateway.registry.require(agent_id).verify_key, payload, signature):
            return BaselineResult("unanimous_signature", False, f"{agent_id}_wrong_signature")
    return BaselineResult("unanimous_signature", True, "all_registered_agents_signed")
