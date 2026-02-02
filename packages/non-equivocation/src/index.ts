import { canonicalizeJson } from "@immuva/canonical";

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
