import fs from "node:fs";
import { createHash } from "node:crypto";
import * as ed from "@noble/ed25519";
import { canonicalizeJson } from "@immuva/canonical";

export type PolicySigEnvelope = {
  version: string;
  algo: string;
  issuer: string;
  policy_id: string;
  issued_at: string | null;

  canonical_json: string;
  canonical_sha256_hex: string;

  signer_public_key_hex: string;
  signature_hex: string;
};

/**
 * Inject sha512 for noble (v3)
 * DONE ONCE, module-level, deterministic
 */
const sha512 = (m: Uint8Array) =>
  createHash("sha512").update(Buffer.from(m)).digest();

(ed.hashes as any).sha512 = sha512;

const sha256 = (b: Uint8Array) =>
  createHash("sha256").update(Buffer.from(b)).digest();

const hexToBytes = (hex: string) =>
  Uint8Array.from(Buffer.from(hex, "hex"));

const bytesToHex = (b: Uint8Array) =>
  Buffer.from(b).toString("hex");

export function loadTrustedPubkeyHex(path: string): string {
  const raw = fs.readFileSync(path);

  // If it's 32 raw bytes -> return hex
  if (raw.length === 32) return bytesToHex(raw);

  // Else try utf8 hex
  const s = raw.toString("utf8").trim();
  if (/^[0-9a-fA-F]{64}$/.test(s)) return s.toLowerCase();

  throw new Error("invalid trusted pubkey format (expected 32 raw bytes or 64 hex chars)");
}

export async function verifyPolicyEnvelope(
  policyObj: any,
  env: PolicySigEnvelope,
  trustedPubHex: string
): Promise<{ ok: true } | { ok: false; code: string }> {

  // 1) trust binding
  if ((env.signer_public_key_hex ?? "").toLowerCase() !== trustedPubHex.toLowerCase()) {
    return { ok: false, code: "POLICY_TRUST_KEY_MISMATCH" };
  }

  // 2) canonical match
  const { canonical } = canonicalizeJson(policyObj);
  if (canonical !== env.canonical_json) {
    return { ok: false, code: "POLICY_CANONICAL_MISMATCH" };
  }

  // 3) sha256(canonical) match
  const hBytes = sha256(Buffer.from(canonical, "utf8"));
  const hHex = Buffer.from(hBytes).toString("hex");

  if ((env.canonical_sha256_hex ?? "").toLowerCase() !== hHex.toLowerCase()) {
    return { ok: false, code: "POLICY_CANONICAL_HASH_MISMATCH" };
  }

  // 4) signature verify (MUST NOT throw)
  try {
    const sig = hexToBytes(env.signature_hex);
    const pub = hexToBytes(trustedPubHex);

    const ok = await ed.verify(sig, hBytes, pub);
    return ok
      ? { ok: true }
      : { ok: false, code: "POLICY_SIGNATURE_INVALID" };

  } catch {
    return { ok: false, code: "POLICY_SIGNATURE_INVALID" };
  }
}
