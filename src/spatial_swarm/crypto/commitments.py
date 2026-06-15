"""Commitments for fragments and transformed proofs."""

from __future__ import annotations

from collections.abc import Iterable

from spatial_swarm.crypto.hashing import sha256_hex

Coord = tuple[int, int, int]


def normalize_coords(coords: Iterable[Coord]) -> list[list[int]]:
    return [[int(x), int(y), int(z)] for x, y, z in sorted(coords)]


def fragment_commitment(agent_id: str, coords: Iterable[Coord], p: int, swarm_id: str) -> str:
    return sha256_hex(
        {
            "kind": "fragment_commitment",
            "swarm_id": swarm_id,
            "agent_id": agent_id,
            "p": p,
            "coords": normalize_coords(coords),
        }
    )


def proof_commitment(
    agent_id: str,
    message_id: str,
    challenge_id: str,
    transformed_coords: Iterable[Coord],
) -> str:
    return sha256_hex(
        {
            "kind": "proof_commitment",
            "agent_id": agent_id,
            "message_id": message_id,
            "challenge_id": challenge_id,
            "coords": normalize_coords(transformed_coords),
        }
    )
