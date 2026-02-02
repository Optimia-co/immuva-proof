export type ViolationCode =
  | "RECEIPT_KIND_NOT_ALLOWED"
  | "RECEIPT_LATE_AFTER_NON_CLOSABLE"
  | "OUTCOME_BASIS_NOT_ALLOWED"
  | "SIGNATURE_INVALID"
  | "KEY_BINDING_MISMATCH"
  | "NON_EQUIVOCATION_VIOLATION"
  | "RESULTSET_MISSING"
  | "RESULTSET_MISSING_BUT_TERMINAL"
  | "EVIDENCE_MISSING"
  | "EVIDENCE_NOT_QUALIFIED"
  | "EVIDENCE_REQUIRED_NOT_MET"
  | "OUTCOME_BASIS_CONFLICT"
  | "NON_CLOSABLE_SIGNAL";

export type StubEvidence = {
  effective: string; // ex: "R1"
  required: string;  // ex: "R2"
  qualified: boolean;
};

export type StubOutcome = {
  value: string;
  basis: string; // ex: "R1"
};

export type StubPointers = {
  action_id: string;
};

export type StubReceipt = {
  kind: string;
};

// --- Crypto suites (v1.1 extension, non-breaking) ---

export type CryptoSuite =
  | "IMMUVAv1-SHA256"
  | "IMMUVAv2-ED25519-SHA256";

export type SigningInfo = {
  /**
   * Cryptographic suite used to produce the signature.
   * - Absent or undefined => implicit v1 (hash-only)
   */
  crypto_suite?: CryptoSuite;

  /**
   * Signature value.
   * - v1: hex(sha256(canonical_event))
   * - v2: Ed25519 signature over sha256(canonical_event)
   */
  signature: string;

  /**
   * Public key required for asymmetric suites (v2+).
   * Must be absent for v1.
   */
  public_key?: string;
};

export type StubSigning = SigningInfo;

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

export type VerdictStatus =
  | "VALID"
  | "INVALID"
  | "PENDING"
  | "AWAITING_EVIDENCE"
  | "NON_CLOSABLE"
  | "CONTESTED";

export type Verdict = {
  status: VerdictStatus;
  evidence?: {
    effective: string;
    required: string;
    qualified: boolean;
  };
  outcome?: {
    value: string;
    basis: string;
  };
  pointers?: {
    action_id: string;
  };
  violations?: string[];
};

export const ALLOWED_RECEIPT_KINDS = new Set(["R1", "R2", "ENV_ATTEST", "NON_CLOSABLE"]);

export function receiptRank(kind: string): number | null {
  const m = /^R(\d+)$/.exec(kind);
  if (!m) return null;
  return parseInt(m[1], 10);
}


export * from "./crypto-suites.js";
