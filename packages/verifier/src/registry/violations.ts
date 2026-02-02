import fs from "fs";
import path from "path";

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

export function loadViolationRegistry(): Map<string, ViolationRegistryEntry> {
  if (cache) return cache;

  const p = path.resolve(
    __dirname,
    "../../../../immuva-proof-spec/registries/v1/violation_codes.json"
  );

  const raw = JSON.parse(fs.readFileSync(p, "utf8"));
  cache = new Map(
    raw.items.map((i: ViolationRegistryEntry) => [i.code, i])
  );

  return cache;
}
