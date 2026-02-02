"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.validateReceiptKindWhitelist = validateReceiptKindWhitelist;
exports.validateNoReceiptAfterNonClosable = validateNoReceiptAfterNonClosable;
exports.hasNonClosableSignal = hasNonClosableSignal;
const protocol_1 = require("@immuva/protocol");
function validateReceiptKindWhitelist(receipts) {
    for (const r of receipts) {
        if (!protocol_1.ALLOWED_RECEIPT_KINDS.has(r.kind))
            return false;
    }
    return true;
}
function validateNoReceiptAfterNonClosable(receipts) {
    const idxNC = receipts.findIndex((r) => r.kind === "NON_CLOSABLE");
    return !(idxNC >= 0 && idxNC < receipts.length - 1);
}
function hasNonClosableSignal(receipts) {
    return receipts.some((r) => r.kind === "NON_CLOSABLE");
}
