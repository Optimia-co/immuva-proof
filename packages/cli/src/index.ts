#!/usr/bin/env node
import "./crypto-init.js";
import { readFileSync } from "node:fs";
import { verifyStub } from "@immuva/verifier";

const args = process.argv.slice(2);
const cmd = args[0];

function usage(): never {
  console.error("Usage: immuva <command> [options]");
  console.error("");
  console.error("Commands:");
  console.error("  verify <proof.json>              Verify a proof");
  console.error("");
  console.error("Options:");
  console.error("  --offline                        Offline mode");
  console.error("  --proof-levels                   Show proof level");
  console.error("  --min-proof-level <level>        Require minimum proof level");
  console.error("                                   Levels: BASIC | KEY_BOUND | TIME_ANCHORED | TRANSPARENCY_LOGGED");
  process.exit(2);
}

if (!cmd || cmd === "--help" || cmd === "-h") usage();

if (cmd === "verify") {
  const file = args[1];
  if (!file || file.startsWith("--")) {
    console.error("Error: missing proof file");
    console.error("Usage: immuva verify <proof.json>");
    process.exit(2);
  }

  let input: any;
  try {
    const raw = readFileSync(file, "utf8");
    input = JSON.parse(raw);
  } catch (e: any) {
    console.error(`Error: cannot read file '${file}': ${e.message}`);
    process.exit(1);
  }

  const offline = args.includes("--offline");

  const minIdx = args.indexOf("--min-proof-level");
  const minProofLevel = minIdx > -1 ? args[minIdx + 1] : undefined;

  const verdict = verifyStub(input, offline, {
    proof_levels: true,
    min_proof_level: minProofLevel,
  });

  const out: any = {};
  if (verdict.mode !== undefined) out.mode = verdict.mode;
  if (verdict.status !== undefined) out.status = verdict.status;
  if ((verdict as any).proof_level !== undefined) out.proof_level = (verdict as any).proof_level;
  if (verdict.evidence !== undefined) out.evidence = verdict.evidence;
  if (verdict.outcome !== undefined) out.outcome = verdict.outcome;
  if (verdict.pointers !== undefined) out.pointers = verdict.pointers;
  if (verdict.violations !== undefined) out.violations = verdict.violations;

  process.stdout.write(JSON.stringify(out, null, 2) + "\n");
  process.exit(0);
}

usage();
