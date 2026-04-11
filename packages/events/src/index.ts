// ── Event kinds ───────────────────────────────────────────────────────────────

export type EventKind =
  | "PAYMENT_DECISION"
  | "FRAUD_CHECK"
  | "APPROVAL"
  | "REJECTION"
  | "AUDIT_LOG"
  | "TOOL_CALL"
  | "LLM_DECISION";

export const STANDARD_KINDS: Record<EventKind, EventKind> = {
  PAYMENT_DECISION: "PAYMENT_DECISION",
  FRAUD_CHECK:      "FRAUD_CHECK",
  APPROVAL:         "APPROVAL",
  REJECTION:        "REJECTION",
  AUDIT_LOG:        "AUDIT_LOG",
  TOOL_CALL:        "TOOL_CALL",
  LLM_DECISION:     "LLM_DECISION",
};

// ── ImmuvaEvent type ──────────────────────────────────────────────────────────

export interface ImmuvaEvent {
  /** Semantic kind of the event */
  kind: EventKind;
  /** Unique identifier for this specific event occurrence */
  action_id: string;
  /** ISO 8601 timestamp of the event */
  timestamp: string;
  /** Arbitrary event-specific data */
  payload: Record<string, unknown>;
}

// ── Factory ───────────────────────────────────────────────────────────────────

/**
 * Create a new ImmuvaEvent with a generated action_id and current timestamp.
 */
export function createEvent(
  kind: EventKind,
  payload: Record<string, unknown>
): ImmuvaEvent {
  return {
    kind,
    action_id: generateId(),
    timestamp: new Date().toISOString(),
    payload,
  };
}

// ── Serialization (canonical JSON — keys sorted recursively) ──────────────────

/**
 * Serialize an event to a canonical JSON string.
 * Keys are sorted lexicographically at every nesting level,
 * matching the @immuva/canonical algorithm.
 */
export function serializeEvent(event: ImmuvaEvent): string {
  return canonicalJSON(event);
}

// ── Internal helpers ──────────────────────────────────────────────────────────

function generateId(): string {
  // Use crypto.randomUUID if available (Node 18+), else fallback
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  // Node.js fallback
  try {
    const { randomUUID } = require("node:crypto");
    return randomUUID();
  } catch {
    return Math.random().toString(36).slice(2) + Date.now().toString(36);
  }
}

function canonicalJSON(value: unknown): string {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return JSON.stringify(value);
  }
  const obj = value as Record<string, unknown>;
  const sorted = Object.keys(obj)
    .sort()
    .map((k) => `${JSON.stringify(k)}:${canonicalJSON(obj[k])}`)
    .join(",");
  return `{${sorted}}`;
}
