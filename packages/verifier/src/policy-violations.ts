export const POLICY_VIOLATION_ORDER = [
  "MIN_PROOF_LEVEL_NOT_MET",
  "KEY_BINDING_REQUIRED",
  "TIME_ANCHOR_REQUIRED",
  "TRANSPARENCY_LOG_REQUIRED"
] as const;

export type PolicyViolationCode = typeof POLICY_VIOLATION_ORDER[number];

const rank = (code: string) => {
  const i = (POLICY_VIOLATION_ORDER as readonly string[]).indexOf(code);
  return i === -1 ? 999 : i;
};

export function uniqAndSortViolations(vios: { code: string }[]): { code: string }[] {
  const seen = new Set<string>();
  const dedup = vios.filter(v => {
    if (seen.has(v.code)) return false;
    seen.add(v.code);
    return true;
  });
  return dedup.sort((a, b) => rank(a.code) - rank(b.code));
}
