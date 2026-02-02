import type {
  ViolationCode,
  VerdictStatus
} from "../../protocol/src/index.js";

export function gateResultset(params: {
  resultset_present?: boolean;
  terminal_present?: boolean;
}): { ok: boolean; status?: VerdictStatus; violations: ViolationCode[] } {
  const present = !!params.resultset_present;
  if (present) return { ok: true, violations: [] };

  const terminal = !!params.terminal_present;
  if (terminal) {
    return { ok: false, status: "INVALID", violations: ["RESULTSET_MISSING_BUT_TERMINAL"] };
  }
  return { ok: false, status: "PENDING", violations: ["RESULTSET_MISSING"] };
}
