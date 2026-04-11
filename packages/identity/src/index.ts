import { sha256HexUtf8 } from "@immuva/canonical";
import { StubInput } from "@immuva/protocol";

export type AgentIdentity = {
  public_key: string;
  key_id: string;
  key_status: "ACTIVE" | "ROTATED" | "REVOKED";
};

export function validateAgentIdentity(keyBinding: any): boolean {
  if (!keyBinding) return false;
  if (!keyBinding.public_key || !keyBinding.key_id) return false;
  // key_id must equal sha256(public_key_hex)
  const expected = sha256HexUtf8(keyBinding.public_key);
  return keyBinding.key_id === expected;
}

export function isKeyActive(keyStatus: string): boolean {
  return keyStatus === "ACTIVE";
}

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
