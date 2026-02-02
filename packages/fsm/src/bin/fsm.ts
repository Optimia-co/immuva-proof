#!/usr/bin/env node
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

type AnyObj = Record<string, any>;

type Violation = {
  code: "FSM_INVALID_ORDER" | "FSM_DOUBLE_FINISH" | "FSM_CROSS_ACTION_ID";
  message: string;
  event_id: string;
};

function isDir(p: string): boolean {
  try { return statSync(p).isDirectory(); } catch { return false; }
}

function readAllInputs(argPath: string): AnyObj[] {
  const inputs: AnyObj[] = [];

  // If a case directory is provided, prefer "<case>/input"
  const base = isDir(argPath) ? argPath : null;
  const inputDir = base && isDir(join(base, "input")) ? join(base, "input") : null;

  if (inputDir) {
    const files = readdirSync(inputDir).map((f) => join(inputDir, f));
    for (const fp of files) {
      if (isDir(fp)) continue;
      inputs.push(...parseFile(fp));
    }
    return inputs;
  }

  // Otherwise treat argPath as a file path
  return parseFile(argPath);
}

function parseFile(fp: string): AnyObj[] {
  const raw = readFileSync(fp, "utf8").trim();
  if (!raw) return [];

  // Try JSON first
  try {
    const v = JSON.parse(raw);
    return Array.isArray(v) ? v : [v];
  } catch {
    // Fallback: JSONL/NDJSON (one json per line)
    const out: AnyObj[] = [];
    for (const line of raw.split(/\r?\n/)) {
      const t = line.trim();
      if (!t) continue;
      out.push(JSON.parse(t));
    }
    return out;
  }
}

function getEventId(e: AnyObj): string {
  return String(e.event_id ?? e.id ?? e.evt_id ?? e.eventId ?? "");
}

function getActionId(e: AnyObj): string {
  return String(e.action_id ?? e.actionId ?? "");
}

function getType(e: AnyObj): string {
  const t = String(e.type ?? e.kind ?? e.event_type ?? e.name ?? "");
  return t;
}

// very small heuristic: look for "start"/"finish" substrings (covers START, start, action.start, etc.)
function isStart(t: string): boolean {
  const s = t.toLowerCase();
  return s.includes("start") || s.includes("begin");
}
function isFinish(t: string): boolean {
  const s = t.toLowerCase();
  return s.includes("finish") || s.includes("end");
}

function runFsm(events: AnyObj[]): { action_id: string; violations: Violation[] } {
  const violations: Violation[] = [];

  let firstAction: string | null = null;
  let seenStart = false;
  let seenFinish = false;

  for (const e of events) {
    const action = getActionId(e);
    const eid = getEventId(e);
    const typ = getType(e);

    if (!firstAction && action) firstAction = action;

    // CROSS_ACTION_ID: any event with a different action_id than the first
    if (firstAction && action && action !== firstAction) {
      violations.push({
        code: "FSM_CROSS_ACTION_ID",
        message: "multiple action_id values observed",
        event_id: eid || "(unknown)"
      });
      // deterministic: stop at first violation
      return { action_id: firstAction, violations };
    }

    // INVALID_ORDER: finish before start
    if (isFinish(typ) && !seenStart) {
      violations.push({
        code: "FSM_INVALID_ORDER",
        message: "finish observed before start",
        event_id: eid || "(unknown)"
      });
      return { action_id: firstAction ?? action ?? "", violations };
    }

    if (isStart(typ)) seenStart = true;

    // DOUBLE_FINISH: more than one finish event
    if (isFinish(typ)) {
      if (seenFinish) {
        violations.push({
          code: "FSM_DOUBLE_FINISH",
          message: "multiple finish events observed",
          event_id: eid || "(unknown)"
        });
        return { action_id: firstAction ?? action ?? "", violations };
      }
      seenFinish = true;
    }
  }

  return { action_id: firstAction ?? "", violations };
}

const arg = process.argv[2];

if (!arg || arg === "--help" || arg === "-h") {
  console.log("Usage: fsm <case_dir_or_file>");
  process.exit(0);
}

const events = readAllInputs(arg);
const out = runFsm(events);

// Must be deterministic and non-failing: print JSON and exit 0
process.stdout.write(JSON.stringify(out, null, 2) + "\n");
process.exit(0);
