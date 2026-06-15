"""One commitment scheme shared by every representation.

The whole experiment holds the commitment fixed and varies only the secret
representation, so this module is the invariant. The construction is identical
across representations -- a SHA-256 over the sorted (order-independent) secret
items plus a representation tag -- so any measured difference is attributable to
the secret format, not the commitment. The tag keeps two representations that
happen to encode the same item set from colliding.
"""

from __future__ import annotations

from collections.abc import Iterable

from spatial_swarm.crypto.hashing import sha256_hex

SecretItem = object  # int (random) or (x, y, z) tuple (geometry)


def _canonical_items(items: Iterable[SecretItem]) -> list:
    """Sorted, order-independent canonical form; coord tuples become lists."""

    return sorted(list(i) if isinstance(i, tuple) else i for i in items)


def commit(swarm_id: str, agent_id: str, repr_name: str, items: Iterable[SecretItem]) -> str:
    return sha256_hex(
        {
            "kind": "spatial_lab_secret",
            "swarm_id": swarm_id,
            "agent_id": agent_id,
            "repr": repr_name,
            "items": _canonical_items(items),
        }
    )


def opens(
    commitment: str,
    swarm_id: str,
    agent_id: str,
    repr_name: str,
    items: Iterable[SecretItem],
) -> bool:
    return commit(swarm_id, agent_id, repr_name, items) == commitment
