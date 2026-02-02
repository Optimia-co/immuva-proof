export type ViolationCode = "RECEIPT_KIND_NOT_ALLOWED" | "RECEIPT_LATE_AFTER_NON_CLOSABLE" | "OUTCOME_BASIS_NOT_ALLOWED" | "SIGNATURE_INVALID" | "KEY_BINDING_MISMATCH" | "NON_EQUIVOCATION_VIOLATION" | "RESULTSET_MISSING" | "RESULTSET_MISSING_BUT_TERMINAL" | "EVIDENCE_MISSING" | "EVIDENCE_NOT_QUALIFIED" | "EVIDENCE_REQUIRED_NOT_MET" | "OUTCOME_BASIS_CONFLICT" | "NON_CLOSABLE_SIGNAL";
export type StubEvidence = {
    effective: string;
    required: string;
    qualified: boolean;
};
export type StubOutcome = {
    value: string;
    basis: string;
};
export type StubPointers = {
    action_id: string;
};
export type StubReceipt = {
    kind: string;
};
export type StubSigning = {
    public_key: string;
    signature: string;
};
export type StubKeyBinding = {
    public_key: string;
};
export type StubInput = {
    resultset_present?: boolean;
    evidence?: StubEvidence;
    outcome?: StubOutcome;
    pointers?: StubPointers;
    receipts?: StubReceipt[];
    canonical_event?: string;
    canonical_events?: string[];
    signing?: StubSigning;
    key_binding?: StubKeyBinding;
    terminal_present?: boolean;
};
export type VerdictStatus = "VALID" | "INVALID" | "PENDING" | "AWAITING_EVIDENCE" | "NON_CLOSABLE" | "CONTESTED";
export type Verdict = {
    status: VerdictStatus;
    evidence?: StubEvidence;
    outcome?: StubOutcome;
    pointers?: StubPointers;
    mode?: "offline";
};
export declare const ALLOWED_RECEIPT_KINDS: Set<string>;
export declare function receiptRank(kind: string): number | null;
