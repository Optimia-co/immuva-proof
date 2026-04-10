#!/usr/bin/env node

/**
 * Immuva FSM CLI (v1)
 * Input  : JSONL (stdin) OR file path argument
 * Output : JSON (stdout)
 *
 * Exit codes:
 *   0 — validation complete (violations array may be non-empty)
 *   1 — internal error (unparseable input, I/O failure, etc.)
 */

import fs from "node:fs";
import { validateFSM } from "../index.js";

function readEvents(): unknown[] {
  const file = process.argv[2];

  let raw = "";
  if (file) {
    raw = fs.readFileSync(file, "utf8");
  } else {
    raw = fs.readFileSync(0, "utf8");
  }

  if (!raw.trim()) {
    throw new Error("FSM_NO_INPUT");
  }

  return raw
    .trim()
    .split(/\r?\n/)
    .map((l) => JSON.parse(l));
}

function output(obj: unknown): void {
  process.stdout.write(JSON.stringify(obj, null, 2));
}

try {
  const events = readEvents();
  const result = validateFSM(events as any);
  output(result);
  process.exit(0);
} catch (err: unknown) {
  const msg = err instanceof Error ? err.message : String(err);
  output({
    action_id: null,
    violations: [
      {
        code: "FSM_INTERNAL_ERROR",
        message: msg,
      },
    ],
  });
  process.exit(1);
}
