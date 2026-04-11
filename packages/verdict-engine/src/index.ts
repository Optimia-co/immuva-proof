import type { StubInput, Verdict } from "@immuva/protocol";

export type VerdictStatus =
  | "VALID"
  | "INVALID"
  | "PENDING"
  | "AWAITING_EVIDENCE"
  | "CONTESTED"
  | "NON_CLOSABLE";

const TERMINAL_STATUSES = new Set<VerdictStatus>(["VALID", "INVALID", "CONTESTED"]);

export function computeVerdict(violations: string[]): VerdictStatus {
  if (violations.length === 0) return "VALID";
  if (violations.includes("RESULTSET_MISSING")) return "PENDING";
  if (violations.includes("EVIDENCE_NOT_QUALIFIED")) return "AWAITING_EVIDENCE";
  if (violations.includes("NON_CLOSABLE_SIGNAL")) return "NON_CLOSABLE";
  if (violations.includes("OUTCOME_BASIS_CONFLICT")) return "CONTESTED";
  return "INVALID";
}

export function isTerminalVerdict(status: VerdictStatus): boolean {
  return TERMINAL_STATUSES.has(status);
}

/**
 * Render a VALID verdict object.
 * Status selection (INVALID/PENDING/…) remains in verifier — this is pure composition.
 */
export function renderValidVerdict(
  input: StubInput,
  opts?: { offline?: boolean }
): Verdict {
  return {
    status: "VALID",
    evidence: input.evidence!,
    outcome: input.outcome!,
    pointers: input.pointers,
    ...(opts?.offline ? { mode: "offline" } : {})
  };
}

// Compatibility alias
export const computeStatus = renderValidVerdict;
