/**
 * Canonical ordering of policy-related violations.
 * Used for deterministic output ordering.
 */

export const POLICY_VIOLATION_ORDER = [
  // A16 – revocation MUST be checked first
  "POLICY_REVOKED",

  // A15 – signature & trust
  "POLICY_SIGNATURE_REQUIRED",
  "POLICY_SIGNATURE_INVALID",
  "POLICY_TRUST_KEY_MISMATCH",

  // Canonical integrity
  "POLICY_CANONICAL_MISMATCH",
  "POLICY_CANONICAL_HASH_MISMATCH",

  // Policy / PRL errors
  "POLICY_REVOCATION_LIST_REQUIRED",
  "POLICY_REVOCATION_LIST_INVALID",

  // Existing protocol requirements
  "MIN_PROOF_LEVEL_NOT_MET",
  "KEY_BINDING_REQUIRED",
  "TIME_ANCHOR_REQUIRED",
  "TRANSPARENCY_LOG_REQUIRED"
] as const;

export type PolicyViolationCode =
  typeof POLICY_VIOLATION_ORDER[number];

const rank = (code: string): number => {
  const i = (POLICY_VIOLATION_ORDER as readonly string[]).indexOf(code);
  return i === -1 ? 999 : i;
};

/**
 * Deduplicate + sort violations deterministically
 */
export function uniqAndSortViolations(
  vios: { code: string }[]
): { code: string }[] {
  const seen = new Set<string>();

  const dedup = vios.filter(v => {
    if (seen.has(v.code)) return false;
    seen.add(v.code);
    return true;
  });

  return dedup.sort((a, b) => rank(a.code) - rank(b.code));
}
