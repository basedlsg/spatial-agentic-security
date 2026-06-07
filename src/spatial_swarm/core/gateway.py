"""USAG gateway: the only communication path between logical agents."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional, Sequence, Union

from nacl.public import PrivateKey

from spatial_swarm.core.agent import LogicalAgent
from spatial_swarm.core.epoch import Epoch
from spatial_swarm.core.message import FrozenMessage, freeze_message
from spatial_swarm.core.registry import AgentRegistration, Registry
from spatial_swarm.core.sidecar import Sidecar
from spatial_swarm.crypto.keys import deterministic_signing_key, generate_gateway_private_key
from spatial_swarm.geometry.finite_grid import FiniteGrid
from spatial_swarm.geometry.fragment import generate_disjoint_fragments
from spatial_swarm.protocol.challenge import Challenge, challenge_for_message
from spatial_swarm.protocol.policies import estimate_envelope
from spatial_swarm.protocol.proof_packet import ProofPacket
from spatial_swarm.protocol.verifier import VerificationResult, Verifier


PacketProvider = Callable[["Gateway", FrozenMessage, Challenge], Sequence[Union[ProofPacket, dict[str, Any]]]]


@dataclass
class Gateway:
    registry: Registry
    sidecars: dict[str, Sidecar]
    agents: dict[str, LogicalAgent]
    private_key: PrivateKey
    grid: FiniteGrid
    verifier: Verifier
    logger: Optional[Any] = None

    @classmethod
    def create_swarm(
        cls,
        agent_count: int = 8,
        fragment_size: int = 16,
        seed: int = 1337,
        p: int = 257,
        timeout_ms: float = 50.0,
        logger: Optional[Any] = None,
    ) -> "Gateway":
        grid = FiniteGrid(p=p)
        epoch = Epoch(index=1).epoch_id
        private_key = generate_gateway_private_key(seed)
        fragments = generate_disjoint_fragments(agent_count, fragment_size, seed, grid)

        registrations: list[AgentRegistration] = []
        sidecars: dict[str, Sidecar] = {}
        for agent_id, fragment in fragments.items():
            signing_key = deterministic_signing_key(seed, agent_id)
            envelope = estimate_envelope(
                agent_id=agent_id,
                epoch=epoch,
                fragment_size=fragment_size,
                p=p,
                timeout_ms=timeout_ms,
            )
            sidecar = Sidecar(
                fragment=fragment,
                signing_key=signing_key,
                gateway_public_key=private_key.public_key,
                epoch=epoch,
                envelope=envelope,
            )
            registrations.append(
                AgentRegistration(
                    agent_id=agent_id,
                    verify_key=sidecar.verify_key,
                    fragment_commitment=sidecar.fragment_commitment,
                    envelope=envelope,
                    fragment=fragment,
                )
            )
            sidecars[agent_id] = sidecar

        registry = Registry(epoch=epoch, registrations=registrations)
        verifier = Verifier(registry=registry, private_key=private_key)
        gateway = cls(
            registry=registry,
            sidecars=sidecars,
            agents={},
            private_key=private_key,
            grid=grid,
            verifier=verifier,
            logger=logger,
        )
        gateway.agents = {
            agent_id: LogicalAgent(agent_id=agent_id, gateway=gateway)
            for agent_id in registry.original_agent_ids
        }
        return gateway

    @property
    def epoch(self) -> str:
        return self.registry.epoch

    def freeze(self, sender_id: str, receiver_id: str, content: Any, nonce: Optional[str] = None) -> FrozenMessage:
        return freeze_message(sender_id, receiver_id, self.epoch, content, nonce)

    def challenge(self, message: FrozenMessage) -> Challenge:
        return challenge_for_message(message, self.grid.p)

    def collect_honest_packets(
        self,
        message: FrozenMessage,
        challenge: Challenge,
        submitted_at_ms: float = 0.0,
    ) -> list[ProofPacket]:
        return [
            self.sidecars[agent_id].build_proof(message, challenge, submitted_at_ms=submitted_at_ms)
            for agent_id in self.registry.original_agent_ids
        ]

    def send(
        self,
        sender_id: str,
        receiver_id: str,
        content: Any,
        nonce: Optional[str] = None,
        packet_provider: Optional[PacketProvider] = None,
    ) -> VerificationResult:
        message = self.freeze(sender_id, receiver_id, content, nonce=nonce)
        challenge = self.challenge(message)
        if self.logger:
            self.logger.emit(
                {
                    "event_type": "message_proposed",
                    "sender_id": sender_id,
                    "receiver_id": receiver_id,
                    "message_id": message.message_id,
                    "challenge_id": challenge.challenge_id,
                    "epoch": message.epoch,
                    "valid": True,
                }
            )

        if packet_provider is None:
            packets = self.collect_honest_packets(message, challenge)
        else:
            packets = list(packet_provider(self, message, challenge))

        result = self.verifier.verify_round(message, challenge, packets)
        if self.logger:
            self.logger.emit_many(event.to_log_dict(self.logger.run_id) for event in result.events)
            self.logger.emit(
                {
                    "event_type": "round_complete",
                    "message_id": message.message_id,
                    "challenge_id": challenge.challenge_id,
                    "epoch": message.epoch,
                    "valid": result.passed,
                    "failure_reason": result.failure_reason,
                    "collapsed": result.collapsed,
                    "latency_ms": result.latency_ms,
                    "proof_bytes": result.proof_bytes_total,
                }
            )
        return result

    def write_demo_visualization_summary(self, path: Path, message: FrozenMessage, challenge: Challenge) -> None:
        from spatial_swarm.geometry.visualization import summarize_point_cloud

        transformed = {
            agent_id: challenge.transform.apply(self.registry.require(agent_id).fragment.coords)
            for agent_id in self.registry.original_agent_ids
        }
        path.write_text(summarize_point_cloud(transformed) + "\n", encoding="utf-8")
