// ── Proof level hierarchy ─────────────────────────────────────────────────────

export type ProofLevel =
  | "BASIC"
  | "KEY_BOUND"
  | "TIME_ANCHORED"
  | "TRANSPARENCY_LOGGED";

export type VerdictStatus =
  | "VALID"
  | "INVALID"
  | "PENDING"
  | "AWAITING_EVIDENCE"
  | "NON_CLOSABLE"
  | "CONTESTED";

const LEVEL_ORDER: Record<ProofLevel, number> = {
  BASIC:               0,
  KEY_BOUND:           1,
  TIME_ANCHORED:       2,
  TRANSPARENCY_LOGGED: 3,
};

// ── Policy types ──────────────────────────────────────────────────────────────

export interface ProofPolicy {
  id: string;
  name: string;
  /** Minimum proof level required for compliance */
  min_proof_level: ProofLevel;
  /** Whether evidence.qualified must be true */
  require_evidence: boolean;
  /** Allowed receipt kinds (empty = any) */
  allowed_receipt_kinds: string[];
  /** Whether verdict status must be VALID */
  require_valid_verdict: boolean;
}

export interface PolicyResult {
  compliant: boolean;
  violations: string[];
  policy_id: string;
}

// ── Validator ─────────────────────────────────────────────────────────────────

export interface ProofSnapshot {
  proof_level?: string | null;
  status?: string | null;
  evidence?: { qualified?: boolean } | null;
  receipt?: { kind?: string } | null;
}

/**
 * Validate a proof against a policy.
 * Returns a PolicyResult with compliant flag and list of violations.
 */
export function validateAgainstPolicy(
  proof: ProofSnapshot,
  policy: ProofPolicy
): PolicyResult {
  const violations: string[] = [];

  // 1. Check proof level
  const level = proof.proof_level as ProofLevel | undefined | null;
  if (!level || LEVEL_ORDER[level] === undefined) {
    violations.push(`proof_level "${level ?? "undefined"}" is not a valid proof level`);
  } else if (LEVEL_ORDER[level] < LEVEL_ORDER[policy.min_proof_level]) {
    violations.push(
      `proof_level "${level}" is below required minimum "${policy.min_proof_level}"`
    );
  }

  // 2. Check verdict status
  if (policy.require_valid_verdict && proof.status !== "VALID") {
    violations.push(`status "${proof.status ?? "undefined"}" must be "VALID"`);
  }

  // 3. Check evidence
  if (policy.require_evidence && !proof.evidence?.qualified) {
    violations.push(`evidence.qualified must be true`);
  }

  // 4. Check receipt kind (only if receipt is present and policy restricts kinds)
  if (
    policy.allowed_receipt_kinds.length > 0 &&
    proof.receipt?.kind &&
    !policy.allowed_receipt_kinds.includes(proof.receipt.kind)
  ) {
    violations.push(
      `receipt.kind "${proof.receipt.kind}" is not in allowed list: [${policy.allowed_receipt_kinds.join(", ")}]`
    );
  }

  return {
    compliant:  violations.length === 0,
    violations,
    policy_id:  policy.id,
  };
}

// ── Standard policies ─────────────────────────────────────────────────────────

export const STANDARD_POLICIES: Record<string, ProofPolicy> = {
  BASIC_COMPLIANCE: {
    id:                   "BASIC_COMPLIANCE",
    name:                 "Basic Compliance",
    min_proof_level:      "KEY_BOUND",
    require_evidence:     false,
    allowed_receipt_kinds: [],
    require_valid_verdict: true,
  },

  EU_AI_ACT_ART13: {
    id:                   "EU_AI_ACT_ART13",
    name:                 "EU AI Act Article 13 — Transparency for High-Risk AI",
    min_proof_level:      "KEY_BOUND",
    require_evidence:     true,
    allowed_receipt_kinds: ["AUDIT_LOG", "LLM_DECISION", "TOOL_CALL"],
    require_valid_verdict: true,
  },

  DORA_AUDIT: {
    id:                   "DORA_AUDIT",
    name:                 "DORA — Digital Operational Resilience Act Audit Trail",
    min_proof_level:      "TIME_ANCHORED",
    require_evidence:     true,
    allowed_receipt_kinds: [],
    require_valid_verdict: true,
  },
};
