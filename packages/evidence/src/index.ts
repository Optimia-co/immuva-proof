import type {
  ViolationCode,
  VerdictStatus,
  StubEvidence,
  StubOutcome,
  StubReceipt
} from "../../protocol/src/index.js";

function receiptRank(kind: string): number | null {
  const m = /^R(\d+)$/.exec(kind);
  if (!m) return null;
  return parseInt(m[1], 10);
}

export function evaluateEvidence(params: {
  evidence?: StubEvidence;
  outcome?: StubOutcome;
  receipts: StubReceipt[];
}): { status: VerdictStatus; violations: ViolationCode[] } {
  const ev = params.evidence;
  if (!ev) return { status: "INVALID", violations: ["EVIDENCE_MISSING"] };

  // basis mismatch => CONTESTED
  if (params.outcome && params.outcome.basis !== ev.effective) {
    return { status: "CONTESTED", violations: ["OUTCOME_BASIS_CONFLICT"] };
  }

  const eff = receiptRank(ev.effective);
  const req = receiptRank(ev.required);
  if (eff === null || req === null) {
    return { status: "INVALID", violations: ["EVIDENCE_REQUIRED_NOT_MET"] };
  }

  const nonClosableSignal = (params.receipts ?? []).some((r) => r.kind === "NON_CLOSABLE");

  // not qualified => degrade
  if (!ev.qualified) {
    return {
      status: nonClosableSignal ? "NON_CLOSABLE" : "AWAITING_EVIDENCE",
      violations: ["EVIDENCE_NOT_QUALIFIED"]
    };
  }

  if (eff >= req) return { status: "VALID", violations: [] };

  return {
    status: nonClosableSignal ? "NON_CLOSABLE" : "AWAITING_EVIDENCE",
    violations: ["EVIDENCE_REQUIRED_NOT_MET"]
  };
}
