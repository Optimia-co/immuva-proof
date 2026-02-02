import { readFileSync } from "node:fs";
import { verifyStub } from "../index";
import type { StubInput } from "@immuva/protocol";

function normalizeVerdictForPrint(v: any) {
  // Ordre voulu par les vectors (JSON compare texte)
  const out: any = {};
  if (v.mode !== undefined) out.mode = v.mode;
  if (v.status !== undefined) out.status = v.status;
  if (v.evidence !== undefined) out.evidence = v.evidence;
  if (v.outcome !== undefined) out.outcome = v.outcome;
  if (v.pointers !== undefined) out.pointers = v.pointers;

  // extensions futures
  if (v.violations !== undefined) out.violations = v.violations;
  if (v.errors !== undefined) out.errors = v.errors;
  return out;
}

const file = process.argv[2];
if (!file || file.startsWith("-")) {
  console.error("Usage: verify <case.json> [--offline]");
  process.exit(2);
}

const offline = process.argv.includes("--offline");

const raw = readFileSync(file, "utf8");
const input = JSON.parse(raw) as StubInput;

const verdict = verifyStub(input, offline);
process.stdout.write(JSON.stringify(normalizeVerdictForPrint(verdict), null, 2) + "\n");
