"""
Immuva Python SDK — compatible with @immuva/verifier v1.x.

Implements IMMUVAv2-ED25519-SHA256:
  canonical_event = json.dumps(event, sort_keys=True, separators=(',', ':'))
  msg_hash        = sha256(canonical_event.encode())
  signature       = ed25519.sign(msg_hash, private_key)
  key_id          = sha256(bytes.fromhex(public_key_hex)).hexdigest()
"""

from .prove import prove
from .verify import verify
from .keygen import keygen

__all__ = ["prove", "verify", "keygen"]
__version__ = "1.0.0"
