"""Key generation helpers."""

from __future__ import annotations

from typing import Optional

from nacl.public import PrivateKey
from nacl.signing import SigningKey

from spatial_swarm.crypto.hashing import hash_bytes


def deterministic_signing_key(seed: int, agent_id: str) -> SigningKey:
    """Create a reproducible Ed25519 signing key for deterministic experiments."""

    return SigningKey(hash_bytes("usag-signing-key", seed, agent_id)[:32])


def generate_gateway_private_key(seed: Optional[int] = None) -> PrivateKey:
    """Create the verifier encryption key.

    A seed is supported for reproducible tests. Real deployments should use random keys.
    """

    if seed is None:
        return PrivateKey.generate()
    return PrivateKey(hash_bytes("usag-gateway-encryption-key", seed)[:32])
