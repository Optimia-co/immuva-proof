import { canonicalizeJson } from "@immuva/canonical";

/**
 * Returns true if two or more canonical events canonicalize to different
 * content — indicating an equivocation attempt.
 */
export function detectEquivocation(events: string[]): boolean {
  if (!events || events.length <= 1) return false;
  const normalized: string[] = [];
  for (const s of events) {
    try {
      const obj = JSON.parse(s);
      normalized.push(canonicalizeJson(obj).canonical);
    } catch {
      // Unparsable event counts as structural violation
      return true;
    }
  }
  return new Set(normalized).size > 1;
}

export function normalizeCanonicalEvents(canonical_events?: string[]): string[] | null {
  if (!canonical_events || canonical_events.length === 0) return [];
  const normalized: string[] = [];
  for (const s of canonical_events) {
    try {
      const obj = JSON.parse(s);
      normalized.push(canonicalizeJson(obj).canonical);
    } catch {
      return null;
    }
  }
  return normalized;
}

export function isNonEquivocating(normalized: string[]): boolean {
  const uniq = new Set(normalized);
  return uniq.size <= 1;
}
