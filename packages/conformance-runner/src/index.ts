import * as fs from "node:fs";
import * as path from "node:path";
import { spawnSync } from "node:child_process";

type Meta = {
  id: string;
  name: string;
  profile: string;
  spec_version: string;
  driver?: "canonicalize" | "fsm" | "verify";
  args?: string[];
};

type RunSummary = {
  profile: string;
  profile_version: string;
  spec_version: string;
  vectors_found: number;
  vectors_passed: number;
  vectors_failed: number;
  failures: Array<{
    vector_dir: string;
    id?: string;
    name?: string;
    reason: string;
    details?: string;
  }>;
};

function readJson(file: string) {
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function exists(p: string) {
  try {
    fs.accessSync(p);
    return true;
  } catch {
    return false;
  }
}

function normalizeText(s: string) {
  // tolère le newline final
  return s.endsWith("\n") ? s.slice(0, -1) : s;
}

function diffFiles(expectedPath: string, actualPath: string): { ok: boolean; reason?: string } {
  if (!exists(expectedPath)) return { ok: false, reason: `missing expected file: ${expectedPath}` };
  if (!exists(actualPath)) return { ok: false, reason: `missing actual file: ${actualPath}` };

  const a = normalizeText(fs.readFileSync(expectedPath, "utf8"));
  const b = normalizeText(fs.readFileSync(actualPath, "utf8"));
  if (a === b) return { ok: true };
  return { ok: false, reason: `mismatch: ${path.basename(expectedPath)}` };
}

function runNode(script: string, args: string[], cwd: string) {
  const r = spawnSync(process.execPath, [script, ...args], {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  return {
    code: r.status ?? 1,
    stdout: r.stdout ?? "",
    stderr: r.stderr ?? "",
  };
}

function listVectorDirs(specConformanceRoot: string): string[] {
  const vectorsRoot = path.join(specConformanceRoot, "vectors");
  const out: string[] = [];
  if (!exists(vectorsRoot)) return out;

  function walk(dir: string) {
    for (const ent of fs.readdirSync(dir, { withFileTypes: true })) {
      const p = path.join(dir, ent.name);
      if (ent.isDirectory()) walk(p);
      else if (ent.isFile() && ent.name === "meta.json") out.push(path.dirname(p));
    }
  }

  walk(vectorsRoot);
  return out.sort();
}

export function runProfile(opts: { profile: string; specPath: string }): RunSummary {
  const profilePath = path.join(opts.specPath, "profiles", `${opts.profile}.json`);
  if (!exists(profilePath)) throw new Error(`profile not found: ${profilePath}`);

  const profileJson = readJson(profilePath) as {
    profile_name: string;
    profile_version: string;
    spec_version: string;
    include: string[];
  };

  const vectorDirs = listVectorDirs(opts.specPath);

  const canonicalBin = path.join(process.cwd(), "packages/canonical/dist/bin/canonicalize.js");
  const fsmBin = path.join(process.cwd(), "packages/fsm/dist/bin/fsm.js");
  const verifyBin = path.join(process.cwd(), "packages/verifier/dist/bin/verify.js");

  const failures: RunSummary["failures"] = [];
  let passed = 0;

  for (const vdir of vectorDirs) {
    const metaFile = path.join(vdir, "meta.json");
    let meta: Meta;

    try {
      meta = readJson(metaFile) as Meta;
    } catch (e: any) {
      failures.push({ vector_dir: vdir, reason: "invalid meta.json", details: String(e?.message ?? e) });
      continue;
    }

    // ignore les vectors hors profile (simple filtre)
    if (meta.profile !== profileJson.profile_name) continue;

    const driver = meta.driver;
    if (!driver) {
      // compat: si pas de driver => pass
      passed += 1;
      continue;
    }

    try {
      if (driver === "canonicalize") {
        if (!exists(canonicalBin)) throw new Error(`missing canonical bin: ${canonicalBin}`);

        const input = path.join(vdir, "input", "event.json");
        const tmpJson = path.join("/tmp", `immuva-${meta.id}-canonical.json`);
        const tmpSha = path.join("/tmp", `immuva-${meta.id}-canonical.sha256`);

        const r = runNode(canonicalBin, [input], process.cwd());
        if (r.code !== 0) throw new Error(`canonicalize failed: ${r.stderr || r.stdout}`);

        fs.writeFileSync(tmpJson, r.stdout, "utf8");
        fs.writeFileSync(tmpSha, r.stderr, "utf8");

        const eJson = path.join(vdir, "expected", "canonical.json");
        const eSha = path.join(vdir, "expected", "canonical.bin.sha256");

        const d1 = diffFiles(eJson, tmpJson);
        const d2 = diffFiles(eSha, tmpSha);
        if (!d1.ok) throw new Error(d1.reason!);
        if (!d2.ok) throw new Error(d2.reason!);

        passed += 1;
        continue;
      }

      if (driver === "fsm") {
        if (!exists(fsmBin)) throw new Error(`missing fsm bin: ${fsmBin}`);

        const input = path.join(vdir, "input", "events.jsonl");
        const tmpOut = path.join("/tmp", `immuva-${meta.id}-violations.json`);

        const r = runNode(fsmBin, [input], process.cwd());
        if (r.code !== 0) throw new Error(`fsm failed: ${r.stderr || r.stdout}`);

        fs.writeFileSync(tmpOut, r.stdout, "utf8");

        const expected = path.join(vdir, "expected", "violations.json");
        const d = diffFiles(expected, tmpOut);
        if (!d.ok) throw new Error(d.reason!);

        passed += 1;
        continue;
      }

      if (driver === "verify") {
        if (!exists(verifyBin)) throw new Error(`missing verifier bin: ${verifyBin}`);

        const input = path.join(vdir, "input", "case.json");
        const args = meta.args ?? [];
        const tmpOut = path.join("/tmp", `immuva-${meta.id}-verdict.json`);

        const r = runNode(verifyBin, [input, ...args], process.cwd());
        if (r.code !== 0) throw new Error(`verify failed: ${r.stderr || r.stdout}`);

        fs.writeFileSync(tmpOut, r.stdout, "utf8");

        const expectedName = args.includes("--offline") ? "verdict_offline.json" : "verdict.json";
        const expected = path.join(vdir, "expected", expectedName);

        const d = diffFiles(expected, tmpOut);
        if (!d.ok) throw new Error(d.reason!);

        passed += 1;
        continue;
      }

      throw new Error(`unknown driver: ${driver}`);
    } catch (e: any) {
      failures.push({
        vector_dir: vdir,
        id: meta?.id,
        name: meta?.name,
        reason: "vector failed",
        details: String(e?.message ?? e),
      });
    }
  }

  return {
    profile: profileJson.profile_name,
    profile_version: profileJson.profile_version,
    spec_version: profileJson.spec_version,
    vectors_found: vectorDirs.filter((d) => {
      try {
        const m = readJson(path.join(d, "meta.json")) as Meta;
        return m.profile === profileJson.profile_name;
      } catch {
        return false;
      }
    }).length,
    vectors_passed: passed,
    vectors_failed: failures.length,
    failures,
  };
}
