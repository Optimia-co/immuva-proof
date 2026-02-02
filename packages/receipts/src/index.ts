import { ALLOWED_RECEIPT_KINDS, StubReceipt } from "@immuva/protocol";

export function validateReceiptKindWhitelist(receipts: StubReceipt[]): boolean {
  for (const r of receipts) {
    if (!ALLOWED_RECEIPT_KINDS.has(r.kind)) return false;
  }
  return true;
}

export function validateNoReceiptAfterNonClosable(receipts: StubReceipt[]): boolean {
  const idxNC = receipts.findIndex((r) => r.kind === "NON_CLOSABLE");
  return !(idxNC >= 0 && idxNC < receipts.length - 1);
}

export function hasNonClosableSignal(receipts: StubReceipt[]): boolean {
  return receipts.some((r) => r.kind === "NON_CLOSABLE");
}
