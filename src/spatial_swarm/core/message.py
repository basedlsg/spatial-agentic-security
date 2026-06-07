"""Message freezing and canonical challenge inputs."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from spatial_swarm.crypto.hashing import canonical_json, sha256_hex


@dataclass(frozen=True)
class FrozenMessage:
    sender_id: str
    receiver_id: str
    epoch: str
    nonce: str
    content: Any
    canonical_message: str
    message_id: str


def freeze_message(
    sender_id: str,
    receiver_id: str,
    epoch: str,
    content: Any,
    nonce: Optional[str] = None,
) -> FrozenMessage:
    canonical_message = canonical_json(content)
    nonce_value = nonce or sha256_hex(
        {
            "sender_id": sender_id,
            "receiver_id": receiver_id,
            "epoch": epoch,
            "content": canonical_message,
        }
    )[:16]
    message_id = sha256_hex(
        {
            "kind": "frozen_message",
            "sender_id": sender_id,
            "receiver_id": receiver_id,
            "epoch": epoch,
            "nonce": nonce_value,
            "canonical_message": canonical_message,
        }
    )
    return FrozenMessage(
        sender_id=sender_id,
        receiver_id=receiver_id,
        epoch=epoch,
        nonce=nonce_value,
        content=content,
        canonical_message=canonical_message,
        message_id=message_id,
    )
