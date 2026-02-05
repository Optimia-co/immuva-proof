import { RegistryProvider } from "./provider";

export type ViolationSeverity =
  | "invalid"
  | "pending"
  | "awaiting_evidence"
  | "contested"
  | "non_closable";

export type ViolationRegistryEntry = {
  code: string;
  severity: ViolationSeverity;
  description: string;
};

let cache: Map<string, ViolationRegistryEntry> | null = null;

export function loadViolationRegistry(
  provider: RegistryProvider,
  version = "v1"
): Map<string, ViolationRegistryEntry> {
  if (cache) return cache;

  const raw = provider.loadJson("violation_codes", version);
  cache = new Map(
    raw.items.map((i: ViolationRegistryEntry) => [i.code, i])
  );

  return cache;
}
