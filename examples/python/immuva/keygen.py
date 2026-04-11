"""Ed25519 key pair generation for Immuva agents."""

import secrets
from typing import TypedDict

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


class KeyPair(TypedDict):
    public_key_hex: str
    private_key_hex: str


def keygen() -> KeyPair:
    """Generate a new Ed25519 key pair.

    Returns:
        A dict with ``public_key_hex`` and ``private_key_hex`` (both 64 hex chars).
    """
    private_key = Ed25519PrivateKey.generate()
    public_key  = private_key.public_key()

    private_bytes = private_key.private_bytes_raw()
    public_bytes  = public_key.public_bytes_raw()

    return {
        "public_key_hex":  public_bytes.hex(),
        "private_key_hex": private_bytes.hex(),
    }
