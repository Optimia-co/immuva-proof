import { canonicalizeJson, sha256HexUtf8 } from "@immuva/canonical";

import type {
  StubInput,
  Verdict,
  StubSigning,
  StubKeyBinding
} from "@immuva/protocol";

import * as ed25519 from "@noble/ed25519";

/**
 * Runtime loader (CommonJS verifier)
 */
async function loadVerifier(): Promise<
  (proof: StubInput, offline: boolean, ctx?: any) => Verdict
> {
  const mod: any = await import("@immuva/verifier");
  return (
    mod.verifyWithDetails ??
    mod.default?.verifyWithDetails ??
    mod.default ??
    mod
  );
}

/* ============================
 * PROVE — V2 ONLY
 * ============================ */
export async function prove(params: {
  event: unknown;
  public_key_hex: string;
  private_key_hex: string;
}): Promise<StubInput> {
  const { canonical } = canonicalizeJson(params.event);

  const msgHash = Buffer.from(sha256HexUtf8(canonical), "hex");
  const sig = await ed25519.sign(
    msgHash,
    Buffer.from(params.private_key_hex, "hex")
  );

  const signing: StubSigning = {
    crypto_suite: "IMMUVAv2-ED25519-SHA256",
    signature: Buffer.from(sig).toString("hex"),
    public_key: params.public_key_hex
  };

  const key_binding: StubKeyBinding = {
    public_key: params.public_key_hex,
      };

  return {
    canonical_event: canonical,
    signing,
    key_binding
  };
}

/* ============================
 * VERIFY — V2 ONLY
 * ============================ */
export async function verify(
  proof: StubInput,
  opts?: { offline?: boolean }
): Promise<Verdict> {
  const offline = opts?.offline ?? true;

  if (
    !proof.signing ||
    proof.signing.crypto_suite !== "IMMUVAv2-ED25519-SHA256" ||
    !proof.signing.public_key
  ) {
    return { status: "INVALID", violations: ["SIGNATURE_INVALID"] };
  }

  const verifyWithDetails = await loadVerifier();
  return verifyWithDetails(proof, offline, { proof_levels: true });
}

/* ============================
 * UTIL
 * ============================ */
export function proofId(proof: StubInput): string {
  return sha256HexUtf8(proof.canonical_event ?? "");
}
