import { sha256HexUtf8 } from "@immuva/canonical"; // (temp)
import type { ViolationCode } from "../../protocol/src/index.js";

export function checkSignature(params: {
  canonical_event: string;
  signature: string;
}): { ok: boolean; violations: ViolationCode[] } {
  const want = sha256HexUtf8(params.canonical_event);
  if (params.signature !== want) {
    return { ok: false, violations: ["SIGNATURE_INVALID"] };
  }
  return { ok: true, violations: [] };
}

export function checkKeyBinding(params: {
  signing_public_key: string;
  binding_public_key: string;
}): { ok: boolean; violations: ViolationCode[] } {
  if (params.signing_public_key !== params.binding_public_key) {
    return { ok: false, violations: ["KEY_BINDING_MISMATCH"] };
  }
  return { ok: true, violations: [] };
}
