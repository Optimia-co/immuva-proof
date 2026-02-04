#!/usr/bin/env node

/**
 * Immuva FSM CLI (v1)
 * Input  : JSONL (stdin) OR file path
 * Output : JSON (stdout)
 */

import fs from "node:fs";

type Violation = {
  code: string;
  message: string;
  event_id?: string;
};

function readEvents(): any[] {
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

function output(obj: any) {
  process.stdout.write(JSON.stringify(obj, null, 2));
}

try {
  const events = readEvents();

  let firstActionId: string | null = null;
  let seenStart = false;
  let finished = false;

  for (const ev of events) {
    if (!ev.action_id) {
      output({
        action_id: null,
        violations: [{ code: "FSM_EVENT_MISSING_ACTION_ID" }],
      });
      process.exit(0);
    }

    if (!firstActionId) {
      firstActionId = ev.action_id;
    } else if (ev.action_id !== firstActionId) {
      output({
        action_id: firstActionId,
        violations: [
          {
            code: "FSM_CROSS_ACTION_ID",
            message: "multiple action_id values observed",
            event_id: ev.event_id,
          },
        ],
      });
      process.exit(0);
    }

    if (ev.kind?.endsWith(".start")) {
      seenStart = true;
    }

    if (ev.kind?.endsWith(".finish")) {
      if (!seenStart) {
        output({
          action_id: firstActionId,
          violations: [
            {
              code: "FSM_INVALID_ORDER",
              message: "finish observed before start",
              event_id: ev.event_id,
            },
          ],
        });
        process.exit(0);
      }

      if (finished) {
        output({
          action_id: firstActionId,
          violations: [
            {
              code: "FSM_DOUBLE_FINISH",
              message: "multiple finish events observed",
              event_id: ev.event_id,
            },
          ],
        });
        process.exit(0);
      }

      finished = true;
    }
  }

  output({
    action_id: firstActionId,
    violations: [],
  });
  process.exit(0);
} catch (err: any) {
  output({
    action_id: null,
    violations: [
      {
        code: "FSM_INTERNAL_ERROR",
        message: err?.message ?? String(err),
      },
    ],
  });
  process.exit(0);
}
