"""USAG gateway: the only communication path between logical agents."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional, Sequence, Union

from nacl.public import PrivateKey

from spatial_swarm.core.agent import LogicalAgent
from spatial_swarm.core.message import FrozenMessage, freeze_message
from spatial_swarm.core.registry import Registry, VerifierPublicSnapshot
from spatial_swarm.core.setup import EphemeralSetup, SetupReport
from spatial_swarm.core.sidecar import Sidecar
from spatial_swarm.core.sidecar_runtime import ProcessSidecarClient
from spatial_swarm.geometry.finite_grid import FiniteGrid
from spatial_swarm.protocol.challenge import Challenge, challenge_for_message
from spatial_swarm.protocol.proof_packet import ProofPacket
from spatial_swarm.protocol.verifier import VerificationResult, Verifier, VerifierOptions


PacketProvider = Callable[["Gateway", FrozenMessage, Challenge], Sequence[Union[ProofPacket, dict[str, Any]]]]


@dataclass
class Gateway:
    registry: Registry
    sidecars: dict[str, Sidecar | ProcessSidecarClient]
    agents: dict[str, LogicalAgent]
    private_key: PrivateKey
    grid: FiniteGrid
    verifier_options: Optional[VerifierOptions] = None
    logger: Optional[Any] = None
    setup_report: Optional[SetupReport] = None
    active_verifier: Optional[Verifier] = None
    last_verifier_shutdown: bool = True
    sidecar_runtime: str = "in_process"

    @classmethod
    def create_swarm(
        cls,
        agent_count: int = 8,
        fragment_size: int = 16,
        seed: int = 1337,
        p: int = 257,
        timeout_ms: float = 50.0,
        logger: Optional[Any] = None,
        verifier_options: Optional[VerifierOptions] = None,
        sidecar_runtime: str = "in_process",
    ) -> "Gateway":
        setup = EphemeralSetup(
            agent_count=agent_count,
            fragment_size=fragment_size,
            seed=seed,
            p=p,
            timeout_ms=timeout_ms,
            sidecar_runtime=sidecar_runtime,
        )
        artifacts = setup.run()
        registry = Registry(epoch=artifacts.registry_epoch, registrations=artifacts.registrations)
        gateway = cls(
            registry=registry,
            sidecars=artifacts.sidecars,
            agents={},
            private_key=artifacts.private_key,
            grid=artifacts.grid,
            verifier_options=verifier_options,
            logger=logger,
            setup_report=artifacts.report,
            sidecar_runtime=sidecar_runtime,
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

    def verifier_public_snapshot_after_setup(self) -> VerifierPublicSnapshot:
        return self.registry.public_snapshot()

    def collect_honest_packets(
        self,
        message: FrozenMessage,
        challenge: Challenge,
        submitted_at_ms: float = 0.0,
    ) -> list[ProofPacket]:
        return [
            self.sidecars[agent_id].submit_proof(message, challenge, submitted_at_ms=submitted_at_ms)
            for agent_id in self.registry.original_agent_ids
        ]

    def shutdown_sidecars(self) -> None:
        for sidecar in self.sidecars.values():
            shutdown = getattr(sidecar, "shutdown", None)
            if shutdown is not None:
                shutdown()

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

        verifier = Verifier(
            registry=self.registry,
            private_key=self.private_key,
            options=self.verifier_options,
        )
        self.active_verifier = verifier
        self.last_verifier_shutdown = False
        try:
            result = verifier.verify_round(message, challenge, packets)
        finally:
            verifier.shutdown()
            self.last_verifier_shutdown = verifier.shutdown_complete
            self.active_verifier = None
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

        if self.sidecar_runtime != "in_process":
            raise RuntimeError("visualization summary requires in-process sidecar material")
        transformed = {
            agent_id: challenge.transform.apply(self.sidecars[agent_id].fragment.coords)
            for agent_id in self.registry.original_agent_ids
        }
        path.write_text(summarize_point_cloud(transformed) + "\n", encoding="utf-8")
