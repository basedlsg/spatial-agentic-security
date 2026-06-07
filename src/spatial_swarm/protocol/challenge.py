"""Message-specific challenge generation."""

from __future__ import annotations

from dataclasses import dataclass

from spatial_swarm.core.message import FrozenMessage
from spatial_swarm.crypto.hashing import sha256_hex
from spatial_swarm.geometry.transform import AffineTransform, transform_from_challenge


@dataclass(frozen=True)
class Challenge:
    challenge_id: str
    transform: AffineTransform


def challenge_for_message(message: FrozenMessage, p: int) -> Challenge:
    challenge_id = sha256_hex(
        {
            "kind": "usag_challenge",
            "canonical_message": message.canonical_message,
            "sender_id": message.sender_id,
            "receiver_id": message.receiver_id,
            "epoch": message.epoch,
            "nonce": message.nonce,
            "message_id": message.message_id,
        }
    )
    return Challenge(challenge_id=challenge_id, transform=transform_from_challenge(challenge_id, p))
