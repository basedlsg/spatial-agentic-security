"""Restricted sidecar runtime clients."""

from __future__ import annotations

from dataclasses import dataclass
from multiprocessing import Pipe, Process
from multiprocessing.connection import Connection
from typing import Any, Optional

from nacl.signing import VerifyKey

from spatial_swarm.core.message import FrozenMessage
from spatial_swarm.core.sidecar import Sidecar
from spatial_swarm.protocol.challenge import Challenge
from spatial_swarm.protocol.policies import ProofEnvelope
from spatial_swarm.protocol.proof_packet import ProofPacket


class SidecarRuntimeError(RuntimeError):
    pass


@dataclass
class ProcessSidecarClient:
    """Parent-side handle for a sidecar running in a child process."""

    agent_id: str
    verify_key: VerifyKey
    fragment_commitment: str
    envelope: ProofEnvelope
    _connection: Connection
    _process: Process
    _closed: bool = False

    @classmethod
    def start(cls, sidecar: Sidecar) -> "ProcessSidecarClient":
        parent_connection, child_connection = Pipe()
        process = Process(
            target=_sidecar_process_loop,
            args=(child_connection, sidecar),
            name=f"usag-sidecar-{sidecar.agent_id}",
        )
        process.start()
        child_connection.close()
        return cls(
            agent_id=sidecar.agent_id,
            verify_key=sidecar.verify_key,
            fragment_commitment=sidecar.fragment_commitment,
            envelope=sidecar.envelope,
            _connection=parent_connection,
            _process=process,
        )

    def health_check(self) -> dict[str, str]:
        return self._request({"op": "health_check"})

    def submit_proof(
        self,
        message: FrozenMessage,
        challenge: Challenge,
        submission_number: int = 1,
        submitted_at_ms: float = 0.0,
        override_message_id: Optional[str] = None,
        override_challenge_id: Optional[str] = None,
    ) -> ProofPacket:
        return self._request(
            {
                "op": "submit_proof",
                "message": message,
                "challenge": challenge,
                "submission_number": submission_number,
                "submitted_at_ms": submitted_at_ms,
                "override_message_id": override_message_id,
                "override_challenge_id": override_challenge_id,
            }
        )

    def rotate_epoch(self, epoch: str, envelope: Optional[ProofEnvelope] = None) -> None:
        self._request({"op": "rotate_epoch", "epoch": epoch, "envelope": envelope})
        if envelope is not None:
            self.envelope = envelope

    def shutdown(self) -> None:
        if self._closed:
            return
        try:
            self._request({"op": "shutdown"})
        finally:
            self._closed = True
            self._connection.close()
            self._process.join(timeout=2.0)
            if self._process.is_alive():
                self._process.terminate()
                self._process.join(timeout=2.0)

    @property
    def is_alive(self) -> bool:
        return self._process.is_alive()

    def _request(self, payload: dict[str, Any]) -> Any:
        if self._closed:
            raise SidecarRuntimeError(f"sidecar {self.agent_id} is shut down")
        self._connection.send(payload)
        response = self._connection.recv()
        if not response.get("ok"):
            raise SidecarRuntimeError(response.get("error", "sidecar command failed"))
        return response.get("result")


def _sidecar_process_loop(connection: Connection, sidecar: Sidecar) -> None:
    try:
        while True:
            request = connection.recv()
            op = request.get("op")
            if op == "health_check":
                connection.send({"ok": True, "result": sidecar.health_check()})
            elif op == "submit_proof":
                packet = sidecar.submit_proof(
                    message=request["message"],
                    challenge=request["challenge"],
                    submission_number=request.get("submission_number", 1),
                    submitted_at_ms=request.get("submitted_at_ms", 0.0),
                    override_message_id=request.get("override_message_id"),
                    override_challenge_id=request.get("override_challenge_id"),
                )
                connection.send({"ok": True, "result": packet})
            elif op == "rotate_epoch":
                sidecar.rotate_epoch(request["epoch"], request.get("envelope"))
                connection.send({"ok": True, "result": None})
            elif op == "shutdown":
                sidecar.shutdown()
                connection.send({"ok": True, "result": None})
                break
            else:
                connection.send({"ok": False, "error": f"unsupported sidecar op: {op!r}"})
    except EOFError:
        pass
    finally:
        connection.close()
