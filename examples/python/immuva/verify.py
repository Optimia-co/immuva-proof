"""Offline ProofBundle verification — IMMUVAv2-ED25519-SHA256."""

import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify(proof: dict[str, Any]) -> dict[str, Any]:
    """Verify an Immuva ProofBundle offline.

    Checks:
    1. Required fields present (canonical_event, signing, key_binding).
    2. crypto_suite is ``IMMUVAv2-ED25519-SHA256``.
    3. Ed25519 signature over sha256(canonical_event) is valid.
    4. key_id == sha256(public_key_hex bytes).

    Returns:
        ``{"status": "VALID"}`` or ``{"status": "INVALID", "violations": [...]}``
    """
    violations: list[str] = []

    canonical = proof.get("canonical_event")
    signing   = proof.get("signing", {})
    binding   = proof.get("key_binding", {})

    if not canonical:
        violations.append("MISSING_CANONICAL_EVENT")
        return {"status": "INVALID", "violations": violations}

    if signing.get("crypto_suite") != "IMMUVAv2-ED25519-SHA256":
        violations.append("UNSUPPORTED_CRYPTO_SUITE")

    sig_hex = signing.get("signature", "")
    pub_hex = signing.get("public_key", "")

    if not sig_hex or not pub_hex:
        violations.append("SIGNATURE_INVALID")
        return {"status": "INVALID", "violations": violations}

    # Verify Ed25519 signature
    try:
        msg_hash   = _sha256(canonical.encode("utf-8"))
        pub_bytes  = bytes.fromhex(pub_hex)
        sig_bytes  = bytes.fromhex(sig_hex)
        public_key = Ed25519PublicKey.from_public_bytes(pub_bytes)
        public_key.verify(sig_bytes, msg_hash)
    except (InvalidSignature, ValueError):
        violations.append("SIGNATURE_INVALID")

    # Verify key_id
    expected_key_id = _sha256_hex(bytes.fromhex(pub_hex)) if pub_hex else ""
    actual_key_id   = binding.get("key_id", "")
    if actual_key_id != expected_key_id:
        violations.append("KEY_ID_MISMATCH")

    if violations:
        return {"status": "INVALID", "violations": violations}

    return {"status": "VALID"}
