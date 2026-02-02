"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ALLOWED_RECEIPT_KINDS = void 0;
exports.receiptRank = receiptRank;
exports.ALLOWED_RECEIPT_KINDS = new Set(["R1", "R2", "ENV_ATTEST", "NON_CLOSABLE"]);
function receiptRank(kind) {
    const m = /^R(\d+)$/.exec(kind);
    if (!m)
        return null;
    return parseInt(m[1], 10);
}
