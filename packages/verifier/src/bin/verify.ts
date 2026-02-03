import fs from "node:fs";
import { readFileSync } from "node:fs";
import { verifyStub } from "../index";
import { loadTrustedPubkeyHex, verifyPolicyEnvelope } from "../policy-signature.js";
import type { StubInput } from "@immuva/protocol";

function normalizeVerdictForPrint(v: any) {
  const out: any = {};
  if (v.mode !== undefined) out.mode = v.mode;
  if (v.status !== undefined) out.status = v.status;
  if (v.evidence !== undefined) out.evidence = v.evidence;
  if (v.outcome !== undefined) out.outcome = v.outcome;
  if (v.pointers !== undefined) out.pointers = v.pointers;
  if (v.violations !== undefined) out.violations = v.violations;
  if (v.errors !== undefined) out.errors = v.errors;
  return out;
}

async function main() {
  const file = process.argv[2];
  if (!file || file.startsWith("-")) {
    console.error("Usage: verify <case.json> [--offline]");
    process.exit(2);
  }

  const offline = process.argv.includes("--offline");
  const proofLevels = process.argv.includes("--proof-levels");

  const minIdx = process.argv.indexOf("--min-proof-level");
  const min = minIdx > -1 ? process.argv[minIdx + 1] : undefined;

  const requireKey = process.argv.includes("--require-key-bound");
  const requireTA = process.argv.includes("--require-time-anchor");
  const requireTL = process.argv.includes("--require-transparency-log");

  const policyIdx = process.argv.indexOf("--policy");
  const policyPath = policyIdx > -1 ? process.argv[policyIdx + 1] : undefined;

  const policySigIdx = process.argv.indexOf("--policy-sig");
  const policySigPath =
    policySigIdx > -1
      ? process.argv[policySigIdx + 1]
      : policyPath
        ? `${policyPath}.sig`
        : undefined;

  const trustIdx = process.argv.indexOf("--policy-trust-key");
  const trustKeyPath = trustIdx > -1 ? process.argv[trustIdx + 1] : undefined;

  const raw = readFileSync(file, "utf8");
  const input = JSON.parse(raw) as StubInput;

  let verifiedPolicy: any = undefined;

  if (policyPath) {
    if (!policySigPath || !fs.existsSync(policySigPath)) {
      process.stdout.write(JSON.stringify(
        { status: "INVALID", violations: [{ code: "POLICY_SIGNATURE_REQUIRED" }] },
        null, 2
      ) + "\n");
      process.exit(0);
    }
    if (!trustKeyPath) {
      process.stdout.write(JSON.stringify(
        { status: "INVALID", violations: [{ code: "POLICY_TRUST_KEY_MISMATCH" }] },
        null, 2
      ) + "\n");
      process.exit(0);
    }

    const pol = JSON.parse(fs.readFileSync(policyPath, "utf8"));
    const env = JSON.parse(fs.readFileSync(policySigPath, "utf8"));
    const trustedPubHex = loadTrustedPubkeyHex(trustKeyPath);

    const r = await verifyPolicyEnvelope(pol, env, trustedPubHex);
    if (!r.ok) {
      process.stdout.write(JSON.stringify(
        { status: "INVALID", violations: [{ code: r.code }] },
        null, 2
      ) + "\n");
      process.exit(0);
    }

    verifiedPolicy = pol;
  }

  const verdict = verifyStub(input, offline, {
    proof_levels: proofLevels,
    min_proof_level: min,
    require_key_bound: requireKey,
    require_time_anchor: requireTA,
    require_transparency_log: requireTL,
    policy: verifiedPolicy
  });

  process.stdout.write(JSON.stringify(normalizeVerdictForPrint(verdict), null, 2) + "\n");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
