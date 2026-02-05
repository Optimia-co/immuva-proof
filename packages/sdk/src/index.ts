import "./crypto-init.js";

import { canonicalizeJson, sha256HexUtf8 } from "../../canonical/dist/index.js";
import type { StubInput, Verdict } from "../../protocol/dist/index.js";
import * as ed25519 from "@noble/ed25519";

/* ============================
 * Runtime verifier loader
 * ============================ */
type VerifyWithDetailsFn =
  (input: any, offline?: boolean, ctx?: any) => any;

async function loadVerifier(): Promise<VerifyWithDetailsFn> {
  // runtime import (verifier built first)
  const mod: any = await import("../../verifier/dist/index.js");
  return mod.verifyWithDetails;
}

/* ============================
 * PROVE — V2 (REAL SIGNATURE)
 * - forwards extra fields
 * - signs sha256(canonical_event)
 * ============================ */
export async function prove(params: any): Promise<any> {
  const {
    event,
    private_key_hex,
    public_key_hex,
    ...rest
  } = params;

  const { canonical } = canonicalizeJson(event);

  // verifier expects Ed25519 over sha256(canonical_event)
  const msgHash = Buffer.from(sha256HexUtf8(canonical), "hex");
  const sig = await ed25519.sign(
    msgHash,
    Buffer.from(private_key_hex, "hex")
  );

  return {
    ...rest,
    canonical_event: canonical,
    signing: {
      crypto_suite: "IMMUVAv2-ED25519-SHA256",
      signature: Buffer.from(sig).toString("hex"),
      public_key: public_key_hex
    },
    key_binding: {
      public_key: public_key_hex,
      key_id: sha256HexUtf8(canonical),
      key_status: "ACTIVE"
    }
  };
}

/* ============================
 * VERIFY — V2
 * ============================ */
export async function verify(proof: any, opts?: any): Promise<any> {

  const offline = opts?.offline ?? true;

  if (
    !proof.signing ||
    proof.signing.crypto_suite !== "IMMUVAv2-ED25519-SHA256" ||
    !proof.signing.public_key ||
    !proof.signing.signature
  ) {
    return {
      status: "INVALID",
      violations: ["SIGNATURE_INVALID"]
    };
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

export { keygen } from "./keygen.js";
