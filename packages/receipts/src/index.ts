import type { ViolationCode, StubReceipt } from "../../protocol/src/index.js";

export const ALLOWED_RECEIPT_KINDS = new Set(["R1", "R2", "ENV_ATTEST", "NON_CLOSABLE"]);

export function receiptRank(kind: string): number | null {
  const m = /^R(\d+)$/.exec(kind);
  if (!m) return null;
  return parseInt(m[1], 10);
}

export function validateReceipts(
  receipts: StubReceipt[],
  outcomeBasis?: string
): { ok: boolean; violations: ViolationCode[] } {
  // 1) kind whitelist
  for (const r of receipts) {
    if (!ALLOWED_RECEIPT_KINDS.has(r.kind)) {
      return { ok: false, violations: ["RECEIPT_KIND_NOT_ALLOWED"] };
    }
  }

  // 2) no receipt after NON_CLOSABLE
  const idxNC = receipts.findIndex((r) => r.kind === "NON_CLOSABLE");
  if (idxNC >= 0 && idxNC < receipts.length - 1) {
    return { ok: false, violations: ["RECEIPT_LATE_AFTER_NON_CLOSABLE"] };
  }

  // 3) ENV_ATTEST cannot be outcome basis
  if (outcomeBasis === "ENV_ATTEST") {
    return { ok: false, violations: ["OUTCOME_BASIS_NOT_ALLOWED"] };
  }

  return { ok: true, violations: [] };
}
