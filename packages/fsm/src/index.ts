type JSONValue =
  | null
  | boolean
  | number
  | string
  | JSONValue[]
  | { [k: string]: JSONValue };

export type Event = {
  kind: string;
  event_id: string;
  action_id: string;
  payload?: JSONValue;
};

export type Violation = {
  code: string;
  message: string;
  event_id?: string;
};

export type FsmResult = {
  action_id: string;
  violations: Violation[];
};

/**
 * FSM v1 (minimal rules for conformance vectors):
 * - Single action_id per stream (first event defines action_id)
 * - "start" must occur before "finish"
 * - only one "finish"
 *
 * NOTE: This is intentionally minimal to lock invariants early.
 */
export function runFsm(events: Event[]): FsmResult {
  const violations: Violation[] = [];
  if (events.length === 0) return { action_id: "", violations };

  const action_id = events[0]?.action_id ?? "";

  let seenStart = false;
  let seenFinish = false;

  for (const ev of events) {
    if (!ev) continue;

    // Rule: cross action_id
    if (ev.action_id !== action_id) {
      violations.push({
        code: "FSM_CROSS_ACTION_ID",
        message: "multiple action_id values observed",
        event_id: ev.event_id,
      });
      // On continue pour détecter d'autres violations aussi (utile plus tard)
    }

    const kind = ev.kind ?? "";

    const isStart = kind.includes("start");
    const isFinish = kind.includes("finish");

    if (isFinish && !seenStart) {
      violations.push({
        code: "FSM_INVALID_ORDER",
        message: "finish observed before start",
        event_id: ev.event_id,
      });
    }

    if (isStart) {
      seenStart = true;
    }

    if (isFinish) {
      if (seenFinish) {
        violations.push({
          code: "FSM_DOUBLE_FINISH",
          message: "multiple finish events observed",
          event_id: ev.event_id,
        });
      }
      seenFinish = true;
    }
  }

  return { action_id, violations };
}
