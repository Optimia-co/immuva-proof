/**
 * @immuva/fsm
 * Finite State Machine validation for Immuva action sequences.
 *
 * Spec reference: spec/v1/J_fsm.md
 *
 * States (J.1):
 *   INIT     → initial, no event seen yet
 *   OPEN     → action in progress (.start received)
 *   FINISHED → action closed (.finish received)
 *   INVALID  → terminal error state
 *
 * Allowed transitions (J.2):
 *   INIT → OPEN        (.start)
 *   OPEN → OPEN        (intermediate events)
 *   OPEN → FINISHED    (.finish)
 *
 * FSM violations are critical (J.5): they produce INVALID immediately,
 * no degradation allowed.
 */

export type FSMState = "INIT" | "OPEN" | "FINISHED" | "INVALID";

export type FSMViolationCode =
  | "FSM_INVALID_ORDER"
  | "FSM_DOUBLE_FINISH"
  | "FSM_CROSS_ACTION_ID"
  | "FSM_EVENT_MISSING_ACTION_ID"
  | "FSM_INTERNAL_ERROR";

export type FSMViolation = {
  code: FSMViolationCode;
  message: string;
  event_id?: string;
};

export type FSMEvent = {
  kind?: string;
  event_id?: string;
  action_id?: string;
  [key: string]: unknown;
};

export type FSMResult = {
  action_id: string | null;
  violations: FSMViolation[];
};

/**
 * Validate a sequence of FSM events against the Immuva state machine spec.
 *
 * Fail-fast: returns on the first violation found.
 *
 * @param events Ordered list of events for a single action.
 * @returns FSMResult with action_id and (possibly empty) violations array.
 */
export function validateFSM(events: FSMEvent[]): FSMResult {
  let firstActionId: string | null = null;
  let state: FSMState = "INIT";

  for (const ev of events) {
    // J.4 — Every event must carry an action_id.
    if (!ev.action_id) {
      return {
        action_id: null,
        violations: [
          {
            code: "FSM_EVENT_MISSING_ACTION_ID",
            message: "event missing action_id",
            event_id: ev.event_id,
          },
        ],
      };
    }

    // J.4 — All events in a proof MUST share the same action_id.
    if (firstActionId === null) {
      firstActionId = ev.action_id;
    } else if (ev.action_id !== firstActionId) {
      return {
        action_id: firstActionId,
        violations: [
          {
            code: "FSM_CROSS_ACTION_ID",
            message: "multiple action_id values observed",
            event_id: ev.event_id,
          },
        ],
      };
    }

    // J.2 / J.3 — State transitions.
    if (ev.kind?.endsWith(".start")) {
      // INIT → OPEN  (multiple .start events stay OPEN — no violation)
      if (state === "INIT" || state === "OPEN") {
        state = "OPEN";
      }
      // .start after FINISHED: falls through — no explicit vector, treated as
      // intermediate event after close (no-op; closure already recorded).
    } else if (ev.kind?.endsWith(".finish")) {
      // J.3 — .finish before any .start  →  FSM_INVALID_ORDER
      if (state === "INIT") {
        return {
          action_id: firstActionId,
          violations: [
            {
              code: "FSM_INVALID_ORDER",
              message: "finish observed before start",
              event_id: ev.event_id,
            },
          ],
        };
      }

      // J.3 — second .finish  →  FSM_DOUBLE_FINISH
      if (state === "FINISHED") {
        return {
          action_id: firstActionId,
          violations: [
            {
              code: "FSM_DOUBLE_FINISH",
              message: "multiple finish events observed",
              event_id: ev.event_id,
            },
          ],
        };
      }

      // OPEN → FINISHED
      state = "FINISHED";
    }
    // Any other kind: intermediate event — OPEN stays OPEN (J.2).
  }

  return {
    action_id: firstActionId,
    violations: [],
  };
}
