"""ProofBundle generation — IMMUVAv2-ED25519-SHA256."""

import hashlib
import json
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def _canonical(event: dict[str, Any]) -> str:
    """Produce the canonical JSON representation (sort_keys, no spaces)."""
    return json.dumps(event, sort_keys=True, separators=(",", ":"))


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def prove(
    event: dict[str, Any],
    public_key_hex: str,
    private_key_hex: str,
    *,
    evidence: dict[str, Any] | None = None,
    outcome: dict[str, Any] | None = None,
    resultset_present: bool = True,
) -> dict[str, Any]:
    """Generate an Immuva ProofBundle.

    The proof is fully compatible with ``@immuva/verifier``:
    - canonical_event = json.dumps(event, sort_keys=True, separators=(',',':'))
    - msg_hash        = sha256(canonical_event.encode('utf-8'))
    - signature       = ed25519.sign(msg_hash, private_key)
    - key_id          = sha256(bytes.fromhex(public_key_hex)).hexdigest()

    Args:
        event:            Dict representing the agent action (will be canonicalized).
        public_key_hex:   Ed25519 public key as a 64-character hex string.
        private_key_hex:  Ed25519 private key as a 64-character hex string.
        evidence:         Optional evidence block (effective, required, qualified).
        outcome:          Optional outcome block (value, basis).
        resultset_present: Include ``resultset_present`` field (default True).

    Returns:
        A ProofBundle dict.
    """
    canonical = _canonical(event)
    msg_hash  = _sha256(canonical.encode("utf-8"))

    private_key_bytes = bytes.fromhex(private_key_hex)
    public_key_bytes  = bytes.fromhex(public_key_hex)

    private_key = Ed25519PrivateKey.from_private_bytes(private_key_bytes)
    signature   = private_key.sign(msg_hash)

    key_id = _sha256_hex(public_key_bytes)

    bundle: dict[str, Any] = {}

    if resultset_present:
        bundle["resultset_present"] = True

    if evidence is not None:
        bundle["evidence"] = evidence

    if outcome is not None:
        bundle["outcome"] = outcome

    bundle["canonical_event"] = canonical
    bundle["signing"] = {
        "crypto_suite": "IMMUVAv2-ED25519-SHA256",
        "signature":    signature.hex(),
        "public_key":   public_key_hex,
    }
    bundle["key_binding"] = {
        "public_key": public_key_hex,
        "key_id":     key_id,
        "key_status": "ACTIVE",
    }

    return bundle
