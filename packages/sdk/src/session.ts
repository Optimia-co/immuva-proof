/**
 * @immuva/sdk — Session mode
 *
 * Optimised for high-frequency environments (inspired by OpenBox):
 * N actions → N individually-verifiable proof bundles
 *              + 1 single Ed25519 signature over the Merkle root
 *
 * The Merkle tree is built from leaves = sha256(canonical_event) for
 * every action in the session. The root is signed once with the agent
 * key, giving a compact batch commitment without sacrificing individual
 * proof verifiability.
 */

import "./crypto-init.js";

import { randomUUID, createHash } from "node:crypto";
import * as ed25519 from "@noble/ed25519";
import { canonicalizeJson, sha256HexUtf8 } from "../../canonical/dist/index.js";
import { merkleRoot } from "../../verifier/dist/tlog/merkle.js";

/* ============================================================
 * Types
 * ============================================================ */

/** One action to be proved inside a session. */
export type SessionEvent = {
  event: Record<string, unknown>;
  evidence: { effective: string; required: string; qualified: boolean };
  outcome: { value: string; basis: string };
  resultset_present?: boolean;
};

/** The output of prove() for a single action. */
export type ProofBundle = {
  canonical_event: string;
  signing: {
    crypto_suite: "IMMUVAv2-ED25519-SHA256";
    signature: string;
    public_key: string;
  };
  key_binding: {
    public_key: string;
    key_id: string;
    key_status: "ACTIVE";
  };
  evidence: { effective: string; required: string; qualified: boolean };
  outcome: { value: string; basis: string };
  resultset_present: boolean;
};

/**
 * A batch of proofs with a single Merkle commitment and session signature.
 *
 * Verification model:
 *  - Each `proof` in `proofs` can be verified individually with @immuva/verifier.
 *  - The `session_signature` is Ed25519(merkle_root, private_key).
 *    Verifiers reconstruct the root from the canonical_event leaves and
 *    check the signature to assert batch integrity.
 */
export type SessionBundle = {
  /** Unique identifier for this session (UUID v4). */
  session_id: string;
  /** Hex-encoded Ed25519 public key that produced every individual signature
   *  and the session_signature. */
  agent_public_key: string;
  /** Individual proof for each action — verifiable in isolation. */
  proofs: ProofBundle[];
  /** Hex-encoded Merkle root over sha256(canonical_event) leaves (RFC 6962). */
  merkle_root: string;
  /** Hex-encoded Ed25519 signature of the raw merkle_root bytes. */
  session_signature: string;
  crypto_suite: "IMMUVAv2-ED25519-SHA256";
  /** ISO 8601 timestamp of session creation. */
  created_at: string;
  event_count: number;
};

/* ============================================================
 * Internal helpers
 * ============================================================ */

/** Canonicalise + sign one event.  Self-contained — no import from index.ts. */
async function proveOne(
  se: SessionEvent,
  public_key_hex: string,
  private_key_hex: string
): Promise<ProofBundle> {
  const { canonical } = canonicalizeJson(se.event);

  // Sign sha256(canonical_event) with Ed25519 — same convention as prove().
  const msgHash = Buffer.from(sha256HexUtf8(canonical), "hex");
  const sig = await ed25519.sign(
    msgHash,
    Buffer.from(private_key_hex, "hex")
  );

  return {
    canonical_event: canonical,
    signing: {
      crypto_suite: "IMMUVAv2-ED25519-SHA256",
      signature: Buffer.from(sig).toString("hex"),
      public_key: public_key_hex,
    },
    key_binding: {
      public_key: public_key_hex,
      key_id: sha256HexUtf8(public_key_hex),
      key_status: "ACTIVE",
    },
    evidence: se.evidence,
    outcome: se.outcome,
    resultset_present: se.resultset_present ?? true,
  };
}

/* ============================================================
 * Public API
 * ============================================================ */

/**
 * Prove a batch of events as a session.
 *
 * Steps:
 *  1. Generate an individual ProofBundle for each SessionEvent.
 *  2. Build a Merkle tree where each leaf is sha256(canonical_event).
 *  3. Sign the Merkle root once with the agent private key.
 *  4. Return the SessionBundle.
 *
 * @param events        Ordered list of session events to prove.
 * @param public_key_hex  Hex-encoded Ed25519 public key.
 * @param private_key_hex Hex-encoded Ed25519 private key (32-byte seed).
 */
export async function proveSession(
  events: SessionEvent[],
  public_key_hex: string,
  private_key_hex: string
): Promise<SessionBundle> {
  if (events.length === 0) {
    throw new Error("proveSession: events array must not be empty");
  }

  // 1. Generate individual proofs in parallel.
  const proofs = await Promise.all(
    events.map(se => proveOne(se, public_key_hex, private_key_hex))
  );

  // 2. Build Merkle leaves: raw canonical_event bytes.
  //    merkleRoot() applies sha256 to each leaf internally — so each leaf
  //    in the tree is sha256(canonical_event), matching the spec description.
  const leaves = proofs.map(p => Buffer.from(p.canonical_event, "utf8"));
  const rootBuffer = merkleRoot(leaves);

  // 3. Hex-encode the Merkle root.
  const merkle_root = rootBuffer.toString("hex");

  // 4. Sign the Merkle root bytes directly (the root is already a 32-byte hash).
  const sessionSig = await ed25519.sign(
    rootBuffer,
    Buffer.from(private_key_hex, "hex")
  );
  const session_signature = Buffer.from(sessionSig).toString("hex");

  return {
    session_id: randomUUID(),
    agent_public_key: public_key_hex,
    proofs,
    merkle_root,
    session_signature,
    crypto_suite: "IMMUVAv2-ED25519-SHA256",
    created_at: new Date().toISOString(),
    event_count: proofs.length,
  };
}
