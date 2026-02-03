import fs from "node:fs";
import { createHash } from "node:crypto";
import * as ed from "@noble/ed25519";
import { canonicalizeJson } from "../packages/canonical/dist/index.js";

/* =========================================================
   REQUIRED for @noble/ed25519 v3 (EXPLICIT HASH BINDINGS)
   ========================================================= */
const sha512 = (msg) => createHash("sha512").update(msg).digest();
ed.etc.sha512Sync = sha512;
ed.hashes.sha512  = sha512;

/* helpers */
function sha256Bytes(buf) {
  return createHash("sha256").update(buf).digest();
}
function hex(buf) {
  return Buffer.from(buf).toString("hex");
}
function arg(name) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : undefined;
}

const keyPath = arg("--key");
const inPath  = arg("--in");
const outPath = arg("--out");

if (!keyPath || !inPath || !outPath) {
  console.error("usage: node tools/policy-sign.mjs --key <immuva-root.key> --in <policy.json> --out <policy.sig>");
  process.exit(2);
}

const keyRaw = fs.readFileSync(keyPath);
if (keyRaw.length < 32) {
  console.error("invalid key: expected >=32 bytes");
  process.exit(2);
}

// Convention: 64 bytes = seed32 || pub32
const seed32 = keyRaw.subarray(0, 32);
const pub32  = keyRaw.length >= 64
  ? keyRaw.subarray(32, 64)
  : await ed.getPublicKey(seed32);

// Canonicalize policy
const policyRaw = JSON.parse(fs.readFileSync(inPath, "utf8"));
const { canonical } = canonicalizeJson(policyRaw);

// Sign sha256(canonical)
const msg = sha256Bytes(Buffer.from(canonical, "utf8"));
const sig = await ed.sign(msg, seed32);

// Signature envelope (A14)
const envelope = {
  version: "1.0.0",
  algo: "ED25519_SHA256_CANONICAL_JSON",
  issuer: policyRaw.issuer ?? "unknown",
  policy_id: policyRaw.policy_id ?? "unknown",
  issued_at: policyRaw.issued_at ?? null,
  canonical_json: canonical,
  canonical_sha256_hex: hex(msg),
  signer_public_key_hex: hex(pub32),
  signature_hex: hex(sig)
};

fs.writeFileSync(outPath, JSON.stringify(envelope, null, 2) + "\n", "utf8");
console.log(`OK: wrote ${outPath}`);
