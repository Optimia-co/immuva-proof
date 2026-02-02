import { readFileSync } from "node:fs";
import { runFsm, Event } from "../index";

const file = process.argv[2];
if (!file) {
  console.error("Usage: fsm <events.jsonl>");
  process.exit(2);
}

const text = readFileSync(file, "utf8").trim();
const lines = text.length ? text.split("\n") : [];
const events: Event[] = lines.map((l) => JSON.parse(l));

const result = runFsm(events);
process.stdout.write(JSON.stringify(result, null, 2) + "\n");
