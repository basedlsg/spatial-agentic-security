"""Deterministic packet mutation fuzzer."""

from __future__ import annotations

import base64
import random
from typing import Any

from nacl.public import SealedBox

from spatial_swarm.core.gateway import Gateway
from spatial_swarm.core.message import FrozenMessage
from spatial_swarm.crypto.commitments import normalize_coords, proof_commitment
from spatial_swarm.crypto.signatures import sign_payload
from spatial_swarm.protocol.challenge import Challenge
from spatial_swarm.protocol.proof_packet import FragmentResponse, ProofPacket


MUTATION_KINDS = (
    "raw_non_dict",
    "agent_id",
    "message_hash",
    "challenge_hash",
    "epoch",
    "signature",
    "encrypted_payload",
    "proof_commitment",
    "packet_size",
    "coordinates",
    "packet_order",
    "submission_number",
    "timestamp",
    "wrong_nonce_transform",
)


class PacketFuzzer:
    def __init__(self, seed: int, mode: str = "single") -> None:
        self.seed = seed
        self.mode = mode

    def packets(
        self,
        gateway: Gateway,
        message: FrozenMessage,
        challenge: Challenge,
    ) -> list[ProofPacket | dict[str, Any] | Any]:
        rng = random.Random(self.seed)
        packets: list[ProofPacket | dict[str, Any] | Any] = gateway.collect_honest_packets(
            message,
            challenge,
        )
        if self.mode == "replay":
            return self._replay_mutation(gateway, message, challenge, rng)
        if self.mode == "mixed":
            for kind in rng.sample(list(MUTATION_KINDS[1:]), k=3):
                packets = self._apply(kind, gateway, message, challenge, packets, rng)
            return packets
        kind = MUTATION_KINDS[self.seed % len(MUTATION_KINDS)]
        return self._apply(kind, gateway, message, challenge, packets, rng)

    def _apply(
        self,
        kind: str,
        gateway: Gateway,
        message: FrozenMessage,
        challenge: Challenge,
        packets: list[ProofPacket | dict[str, Any] | Any],
        rng: random.Random,
    ) -> list[ProofPacket | dict[str, Any] | Any]:
        if kind == "raw_non_dict":
            return [None]
        if kind == "packet_order":
            first = packets[0]
            return [first, first, *packets[2:]]

        target_index = rng.randrange(len(packets))
        target = packets[target_index]
        if not isinstance(target, ProofPacket):
            return packets
        mutated = self._mutate_packet(kind, gateway, message, challenge, target, rng)
        return [mutated if index == target_index else packet for index, packet in enumerate(packets)]

    def _mutate_packet(
        self,
        kind: str,
        gateway: Gateway,
        message: FrozenMessage,
        challenge: Challenge,
        packet: ProofPacket,
        rng: random.Random,
    ) -> ProofPacket | dict[str, Any]:
        fields = packet.as_dict()
        if kind == "agent_id":
            fields["agent_id"] = "agent_999"
            return fields
        if kind == "message_hash":
            fields["message_id"] = "f" * 64
            return self._resign(gateway, packet.agent_id, fields)
        if kind == "challenge_hash":
            fields["challenge_id"] = "e" * 64
            return self._resign(gateway, packet.agent_id, fields)
        if kind == "epoch":
            fields["epoch"] = "epoch_wrong"
            return self._resign(gateway, packet.agent_id, fields)
        if kind == "signature":
            first = fields["signature"][0] if fields["signature"] else "A"
            replacement = "B" if first == "A" else "A"
            fields["signature"] = replacement + fields["signature"][1:]
            return ProofPacket(**fields)
        if kind == "encrypted_payload":
            fields["encrypted_fragment_response"] = "not-base64!"
            return self._resign(gateway, packet.agent_id, fields)
        if kind == "proof_commitment":
            fields["proof_commitment"] = "0" * 64
            return self._resign(gateway, packet.agent_id, fields)
        if kind == "packet_size":
            fields["encrypted_fragment_response"] += "A" * 50_000
            return self._resign(gateway, packet.agent_id, fields)
        if kind == "coordinates":
            return self._wrong_coordinates(gateway, message, challenge, packet.agent_id, rng)
        if kind == "submission_number":
            fields["submission_number"] = 2
            return self._resign(gateway, packet.agent_id, fields)
        if kind == "timestamp":
            fields["submitted_at_ms"] = gateway.registry.require(packet.agent_id).envelope.timeout_ms + 1.0
            return self._resign(gateway, packet.agent_id, fields)
        if kind == "wrong_nonce_transform":
            return self._wrong_nonce_transform(gateway, message, challenge, packet.agent_id)
        return packet

    def _replay_mutation(
        self,
        gateway: Gateway,
        message: FrozenMessage,
        challenge: Challenge,
        rng: random.Random,
    ) -> list[ProofPacket]:
        old_message = gateway.freeze(message.sender_id, message.receiver_id, message.content, nonce="fuzz-old")
        old_challenge = gateway.challenge(old_message)
        old_packets = gateway.collect_honest_packets(old_message, old_challenge)
        current_packets = gateway.collect_honest_packets(message, challenge)
        target_index = rng.randrange(len(current_packets))
        current_packets[target_index] = old_packets[target_index]
        return current_packets

    def _wrong_coordinates(
        self,
        gateway: Gateway,
        message: FrozenMessage,
        challenge: Challenge,
        agent_id: str,
        rng: random.Random,
    ) -> ProofPacket:
        coords = set(challenge.transform.apply(gateway.sidecars[agent_id].fragment.coords))
        x, y, z = next(iter(coords))
        coords.remove((x, y, z))
        coords.add(((x + rng.randrange(1, gateway.grid.p)) % gateway.grid.p, y, z))
        return self._signed_response(gateway, message, challenge, agent_id, coords)

    def _wrong_nonce_transform(
        self,
        gateway: Gateway,
        message: FrozenMessage,
        challenge: Challenge,
        agent_id: str,
    ) -> ProofPacket:
        other_message = gateway.freeze(
            message.sender_id,
            message.receiver_id,
            message.content,
            nonce=f"{message.nonce}:fuzz-wrong-transform",
        )
        other_challenge = gateway.challenge(other_message)
        coords = other_challenge.transform.apply(gateway.sidecars[agent_id].fragment.coords)
        return self._signed_response(gateway, message, challenge, agent_id, coords)

    def _signed_response(
        self,
        gateway: Gateway,
        message: FrozenMessage,
        challenge: Challenge,
        agent_id: str,
        coords: set[tuple[int, int, int]],
    ) -> ProofPacket:
        registration = gateway.registry.require(agent_id)
        response = FragmentResponse(
            agent_id=agent_id,
            message_id=message.message_id,
            challenge_id=challenge.challenge_id,
            fragment_commitment=registration.fragment_commitment,
            coords=normalize_coords(coords),
        )
        encrypted = SealedBox(gateway.private_key.public_key).encrypt(
            response.model_dump_json().encode("utf-8")
        )
        fields: dict[str, Any] = {
            "agent_id": agent_id,
            "swarm_id": gateway.swarm_id,
            "epoch": gateway.epoch,
            "message_id": message.message_id,
            "challenge_id": challenge.challenge_id,
            "proof_version": "v1",
            "submission_number": 1,
            "proof_commitment": proof_commitment(
                agent_id,
                message.message_id,
                challenge.challenge_id,
                coords,
            ),
            "encrypted_fragment_response": base64.b64encode(encrypted).decode("ascii"),
            "signature": "",
            "submitted_at_ms": 0.0,
        }
        return self._resign(gateway, agent_id, fields)

    def _resign(self, gateway: Gateway, agent_id: str, fields: dict[str, Any]) -> ProofPacket:
        fields = dict(fields)
        fields["signature"] = ""
        unsigned = ProofPacket(**fields)
        fields["signature"] = sign_payload(
            gateway.sidecars[agent_id].signing_key,
            unsigned.signed_payload(),
        )
        return ProofPacket(**fields)
