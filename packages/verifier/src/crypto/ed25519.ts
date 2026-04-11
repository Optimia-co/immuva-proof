import * as ed25519 from "@noble/ed25519";
import { createHash } from "node:crypto";

// Noble ed25519 v3 requires explicit sha512 injection.
// This module-level side effect runs once on first import.
(ed25519.hashes as any).sha512 = (m: Uint8Array) =>
  createHash("sha512").update(Buffer.from(m)).digest();

/**
 * Verify an Ed25519 signature over sha256(canonical_event).
 * Deterministic, synchronous, side-effect free.
 */
export function verifyEd25519Signature(
  canonicalEvent: string,
  signatureHex: string,
  publicKeyHex: string
): boolean {
  try {
    const msgHash = createHash("sha256")
      .update(canonicalEvent, "utf8")
      .digest();

    const signature = Uint8Array.from(Buffer.from(signatureHex, "hex"));
    const publicKey = Uint8Array.from(Buffer.from(publicKeyHex, "hex"));

    return ed25519.verify(signature, msgHash, publicKey);
  } catch {
    return false;
  }
}
