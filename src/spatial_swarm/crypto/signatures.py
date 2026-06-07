"""Ed25519 signature helpers."""

from __future__ import annotations

import base64
from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey

from spatial_swarm.crypto.hashing import canonical_json


def sign_payload(signing_key: SigningKey, payload: dict[str, Any]) -> str:
    signed = signing_key.sign(canonical_json(payload).encode("utf-8"))
    return base64.b64encode(signed.signature).decode("ascii")


def verify_payload(verify_key: VerifyKey, payload: dict[str, Any], signature_b64: str) -> bool:
    try:
        signature = base64.b64decode(signature_b64.encode("ascii"), validate=True)
        verify_key.verify(canonical_json(payload).encode("utf-8"), signature)
        return True
    except (BadSignatureError, ValueError):
        return False
