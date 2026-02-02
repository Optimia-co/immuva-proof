import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import path from "node:path";

export type RegistryManifest = {
  manifest_version: string;
  created_at: string;
  spec_version: string;
  registries_version: string;
  files: Array<{ path: string; sha256: string }>;
};

export function sha256File(absPath: string): string {
  const data = readFileSync(absPath);
  return createHash("sha256").update(data).digest("hex");
}

export function loadManifest(specRegistriesDir: string): RegistryManifest {
  const p = path.join(specRegistriesDir, "manifests", "registry-manifest.json");
  return JSON.parse(readFileSync(p, "utf8"));
}

export function validateManifestSha(specRegistriesDir: string): { ok: boolean; errors: string[] } {
  const m = loadManifest(specRegistriesDir);
  const errors: string[] = [];
  for (const f of m.files) {
    const abs = path.join(specRegistriesDir, f.path);
    const actual = sha256File(abs);
    if (!f.sha256 || f.sha256 !== actual) {
      errors.push(`sha256 mismatch for ${f.path}: expected=${f.sha256} actual=${actual}`);
    }
  }
  return { ok: errors.length === 0, errors };
}
