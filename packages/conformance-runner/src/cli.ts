import * as path from "node:path";
import { runProfile } from "./index.js";

function usage(): never {
  console.error(
    "Usage: conformance-runner run --profile <core|tl|policies> --spec <path-to-conformance-v1>\n" +
    "Example: conformance-runner run --profile core --spec ../immuva-proof-spec/conformance/v1"
  );
  process.exit(2);
}

function getFlag(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  if (i === -1) return undefined;
  const v = args[i + 1];
  if (!v || v.startsWith("--")) return undefined;
  return v;
}

const args = process.argv.slice(2);
const cmd = args[0];
if (!cmd) usage();

if (cmd !== "run") usage();

const profile = getFlag(args, "--profile");
const spec = getFlag(args, "--spec");

if (!profile || !spec) usage();

// normalise: si user passe un chemin relatif, on le resolve depuis CWD
const specPath = path.resolve(process.cwd(), spec);

const summary = runProfile({ profile, specPath });
process.stdout.write(JSON.stringify(summary, null, 2) + "\n");
