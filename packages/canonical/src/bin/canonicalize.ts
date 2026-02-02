import { readFileSync } from "node:fs";
import { canonicalizeJson } from "../index";

const file = process.argv[2];
if (!file) {
  console.error("Usage: canonicalize <jsonfile>");
  process.exit(2);
}
const raw = readFileSync(file, "utf8");
const obj = JSON.parse(raw);

const { canonical, sha256 } = canonicalizeJson(obj);
process.stdout.write(canonical + "\n");
process.stderr.write(sha256 + "\n");
