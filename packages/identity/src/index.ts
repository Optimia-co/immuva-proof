import { sha256HexUtf8 } from "../../canonical/dist/index.js";
import { StubInput } from "@immuva/protocol";

export function validateSignatureModelV1(input: StubInput): boolean {
  if (!input.signing) return true;
  const canonical = input.canonical_event ?? "";
  const want = sha256HexUtf8(canonical);
  return input.signing.signature === want;
}

export function validateKeyBinding(input: StubInput): boolean {
  if (!input.key_binding || !input.signing) return true;
  return input.key_binding.public_key === input.signing.public_key;
}
