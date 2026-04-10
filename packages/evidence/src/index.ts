/**
 * @immuva/evidence
 * Validation helpers for the evidence block of an Immuva proof.
 *
 * An evidence block asserts:
 *   - effective : the receipt kind that was actually collected (e.g. "R1")
 *   - required  : the minimum receipt kind required by the policy (e.g. "R2")
 *   - qualified : whether the evidence is considered sufficient for the claim
 *
 * Receipt ranks (Rn) are compared numerically: R2 > R1.
 */

export type Evidence = {
  /** Receipt kind actually obtained, e.g. "R1", "R2" */
  effective: string;
  /** Minimum receipt kind required by the policy */
  required: string;
  /** Whether the evidence meets qualitative criteria beyond rank */
  qualified: boolean;
};

export type EvidenceViolation =
  | "EVIDENCE_MISSING"
  | "EVIDENCE_REQUIRED_NOT_MET"
  | "EVIDENCE_NOT_QUALIFIED";

export type EvidenceResult =
  | { ok: true }
  | { ok: false; violation: EvidenceViolation; details?: string };

/**
 * Parse the numeric rank from a receipt kind string ("R1" → 1, "R2" → 2).
 * Returns null for non-Rn kinds (e.g. "ENV_ATTEST", "NON_CLOSABLE").
 */
export function receiptRank(kind: string): number | null {
  const m = /^R(\d+)$/.exec(kind);
  return m ? parseInt(m[1], 10) : null;
}

/**
 * Validate that an evidence block is structurally valid and complete.
 *
 * Rules (in order):
 * 1. evidence must be present
 * 2. effective and required must be parseable Rn kinds
 * 3. effective rank must be >= required rank
 * 4. qualified must be true
 */
export function validateEvidence(ev: Evidence | undefined | null): EvidenceResult {
  if (!ev) {
    return { ok: false, violation: "EVIDENCE_MISSING" };
  }

  const eff = receiptRank(ev.effective);
  const req = receiptRank(ev.required);

  if (eff === null || req === null) {
    return {
      ok: false,
      violation: "EVIDENCE_REQUIRED_NOT_MET",
      details: `Non-Rn receipt kind: effective="${ev.effective}" required="${ev.required}"`,
    };
  }

  if (eff < req) {
    return {
      ok: false,
      violation: "EVIDENCE_REQUIRED_NOT_MET",
      details: `effective rank ${eff} < required rank ${req}`,
    };
  }

  if (!ev.qualified) {
    return { ok: false, violation: "EVIDENCE_NOT_QUALIFIED" };
  }

  return { ok: true };
}

/**
 * Returns true when evidence is present, ranked, and qualified.
 * Convenience wrapper around validateEvidence.
 */
export function isEvidenceSufficient(ev: Evidence | undefined | null): boolean {
  return validateEvidence(ev).ok;
}

/**
 * Determine the degraded state when evidence is insufficient.
 * Mirrors the degradation logic in the core verifier.
 *
 * - Not qualified → "AWAITING_EVIDENCE" (or "NON_CLOSABLE" when signalled)
 * - Qualified but rank insufficient → same degradation
 */
export function degradeEvidence(
  ev: Evidence,
  nonClosableSignal: boolean
): "AWAITING_EVIDENCE" | "NON_CLOSABLE" {
  return nonClosableSignal ? "NON_CLOSABLE" : "AWAITING_EVIDENCE";
}
