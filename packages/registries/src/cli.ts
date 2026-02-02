#!/usr/bin/env node
import { validateManifestSha } from "./index.js";

function usage(): never {
  console.error("Usage:");
  console.error("  immuva-registries validate --spec <path-to-registries-v1>");
  process.exit(2);
}

const args = process.argv.slice(2);
if (args.length === 0) usage();

const cmd = args[0];
if (cmd !== "validate") usage();

const specIdx = args.indexOf("--spec");
if (specIdx === -1 || !args[specIdx + 1]) usage();
const specPath = args[specIdx + 1];

const res = validateManifestSha(specPath);
if (!res.ok) {
  console.error("REGISTRIES INVALID:");
  for (const e of res.errors) console.error(" -", e);
  process.exit(1);
}
console.log("REGISTRIES OK (manifest sha256 match)");
