"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.computeStatus = computeStatus;
const protocol_1 = require("@immuva/protocol");
const receipts_1 = require("@immuva/receipts");
const identity_1 = require("@immuva/identity");
const non_equivocation_1 = require("@immuva/non-equivocation");
function computeStatus(input) {
    const violations = [];
    const ret = (status) => ({ status, violations });
    const fail = (code, status) => {
        violations.push(code);
        return ret(status);
    };
    const receipts = input.receipts ?? [];
    // 1) receipt kind whitelist
    if (!(0, receipts_1.validateReceiptKindWhitelist)(receipts))
        return fail("RECEIPT_KIND_NOT_ALLOWED", "INVALID");
    // 2) no receipt after NON_CLOSABLE
    if (!(0, receipts_1.validateNoReceiptAfterNonClosable)(receipts))
        return fail("RECEIPT_LATE_AFTER_NON_CLOSABLE", "INVALID");
    // 3) ENV_ATTEST cannot be outcome basis
    if (input.outcome?.basis === "ENV_ATTEST")
        return fail("OUTCOME_BASIS_NOT_ALLOWED", "INVALID");
    // 4) signature model v1
    if (!(0, identity_1.validateSignatureModelV1)(input))
        return fail("SIGNATURE_INVALID", "INVALID");
    // 5) key binding must match signing
    if (!(0, identity_1.validateKeyBinding)(input))
        return fail("KEY_BINDING_MISMATCH", "INVALID");
    // 6) non-equivocation
    const normalized = (0, non_equivocation_1.normalizeCanonicalEvents)(input.canonical_events);
    if (normalized === null)
        return fail("NON_EQUIVOCATION_VIOLATION", "INVALID");
    if (normalized.length > 0 && !(0, non_equivocation_1.isNonEquivocating)(normalized))
        return fail("NON_EQUIVOCATION_VIOLATION", "INVALID");
    // 7) ResultSet gate
    const hasResultset = input.resultset_present === true;
    if (!hasResultset) {
        const attemptingToConclude = input.terminal_present === true ||
            input.outcome !== undefined;
        if (attemptingToConclude) {
            return fail("RESULTSET_MISSING", "INVALID");
        }
        return ret("PENDING");
    }
    // 8) Evidence required
    const ev = input.evidence;
    if (!ev)
        return fail("EVIDENCE_MISSING", "INVALID");
    // 9) Basis conflict
    if (input.outcome && input.outcome.basis !== ev.effective) {
        return fail("OUTCOME_BASIS_CONFLICT", "CONTESTED");
    }
    // 10) Evidence evaluation
    const eff = (0, protocol_1.receiptRank)(ev.effective);
    const req = (0, protocol_1.receiptRank)(ev.required);
    if (eff === null || req === null)
        return fail("EVIDENCE_REQUIRED_NOT_MET", "INVALID");
    const nonClosable = (0, receipts_1.hasNonClosableSignal)(receipts);
    if (!ev.qualified) {
        violations.push("EVIDENCE_NOT_QUALIFIED");
        return ret(nonClosable ? "NON_CLOSABLE" : "AWAITING_EVIDENCE");
    }
    if (eff >= req)
        return ret("VALID");
    violations.push("EVIDENCE_REQUIRED_NOT_MET");
    return ret(nonClosable ? "NON_CLOSABLE" : "AWAITING_EVIDENCE");
}
