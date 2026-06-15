"""Attestation -- a local stub on this machine (no SGX hardware).

On real SGX, attestation produces a DCAP quote binding the enclave measurement. Here
the measurement is a deterministic stand-in (a hash of the sealed-service source), and
`sgx=False` marks that this provides no hardware confidentiality. See the cloud-SGX
runbook for the hardware path.
"""

from __future__ import annotations

import pathlib
from dataclasses import dataclass

from spatial_swarm.crypto.hashing import sha256_hex


@dataclass(frozen=True)
class Attestation:
    mode: str
    measurement: str
    sgx: bool


def _code_measurement() -> str:
    here = pathlib.Path(__file__).parent
    parts = []
    for name in ("service.py", "failure_policy.py", "zeroize.py", "attestation.py"):
        f = here / name
        parts.append(sha256_hex(f.read_bytes()) if f.exists() else name)
    return sha256_hex({"kind": "spatial_puzzle_enclave_measurement", "parts": parts})


def attest() -> Attestation:
    return Attestation(mode="stub_local", measurement=_code_measurement(), sgx=False)
