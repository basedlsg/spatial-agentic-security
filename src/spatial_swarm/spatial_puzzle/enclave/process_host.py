"""Run the sealed service in a child process behind a restricted pipe API.

The parent (untrusted host) holds only a client that can invoke the allowlisted ops;
the SealedService and its private state live in the child. This is the local,
software-level analog of an enclave boundary (reuses the core sidecar-runtime pipe
pattern). It does not defend a compromised host -- that needs SGX (see the runbook).
"""

from __future__ import annotations

from multiprocessing import Pipe, Process
from multiprocessing.connection import Connection

from spatial_swarm.spatial_puzzle.enclave.service import ALLOWED_OPS, SealedService


class SealedServiceError(RuntimeError):
    pass


def _loop(conn: Connection, one_shot: bool, expose_outer_shape: bool) -> None:
    service = SealedService(one_shot=one_shot, expose_outer_shape=expose_outer_shape)
    try:
        while True:
            req = conn.recv()
            op = req.get("op")
            if op == "__shutdown__":
                conn.send({"ok": True, "result": None})
                break
            if op not in ALLOWED_OPS:
                conn.send({"ok": False, "error": f"forbidden op: {op!r}"})
                continue
            try:
                result = getattr(service, op)(*req.get("args", ()), **req.get("kwargs", {}))
                conn.send({"ok": True, "result": result})
            except Exception as exc:  # pragma: no cover - defensive
                conn.send({"ok": False, "error": f"{type(exc).__name__}: {exc}"})
    except EOFError:
        pass
    finally:
        conn.close()


class SealedServiceClient:
    def __init__(self, conn: Connection, proc: Process) -> None:
        self._conn = conn
        self._proc = proc
        self._closed = False

    @classmethod
    def start(cls, one_shot: bool = True, expose_outer_shape: bool = False) -> "SealedServiceClient":
        parent, child = Pipe()
        proc = Process(target=_loop, args=(child, one_shot, expose_outer_shape), name="spatial-puzzle-enclave")
        proc.start()
        child.close()
        return cls(parent, proc)

    def call(self, op: str, *args, **kwargs):
        if self._closed:
            raise SealedServiceError("sealed service is shut down")
        self._conn.send({"op": op, "args": args, "kwargs": kwargs})
        resp = self._conn.recv()
        if not resp.get("ok"):
            raise SealedServiceError(resp.get("error", "sealed service error"))
        return resp.get("result")

    # allowlisted convenience wrappers
    def create_swarm(self, **kwargs):
        return self.call("create_swarm", **kwargs)

    def issue_agent_package(self, swarm_id, agent_id):
        return self.call("issue_agent_package", swarm_id, agent_id)

    def verify_message(self, swarm_id, agent_id, candidate):
        return self.call("verify_message", swarm_id, agent_id, candidate)

    def destroy_swarm(self, swarm_id, reason="requested"):
        return self.call("destroy_swarm", swarm_id, reason)

    def attest(self):
        return self.call("attest")

    def public_metadata(self, swarm_id):
        return self.call("public_metadata", swarm_id)

    @property
    def is_alive(self) -> bool:
        return self._proc.is_alive()

    def shutdown(self) -> None:
        if self._closed:
            return
        try:
            self._conn.send({"op": "__shutdown__"})
            self._conn.recv()
        except (EOFError, OSError):
            pass
        finally:
            self._closed = True
            self._conn.close()
            self._proc.join(timeout=2.0)
            if self._proc.is_alive():
                self._proc.terminate()
                self._proc.join(timeout=2.0)
