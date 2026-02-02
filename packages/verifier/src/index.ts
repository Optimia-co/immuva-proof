import { sha256HexUtf8, canonicalizeJson } from "../../canonical/dist/index.js";

type JSONValue =
  | null
  | boolean
  | number
  | string
  | JSONValue[]
  | { [k: string]: JSONValue };

export type StubEvidence = {
  effective: string; // ex: "R1"
  required: string;  // ex: "R2"
  qualified: boolean;
};

export type StubOutcome = {
  value: string;
  basis: string; // ex: "R1"
};

export type StubPointers = {
  action_id: string;
};

export type StubReceipt = {
  kind: string;
};

export type StubSigning = {
  public_key: string;
  signature: string; // hex(sha256(canonical_event)) for now
};

export type StubKeyBinding = {
  public_key: string;
};

export type StubInput = {
  // T-min gate: "present" explicit, absent/false means "no resultset yet"
  resultset_present?: boolean;

  evidence?: StubEvidence;
  outcome?: StubOutcome;
  pointers?: StubPointers;

  // optional extensions for next vectors
  receipts?: StubReceipt[];

  canonical_event?: string;
  canonical_events?: string[];

  signing?: StubSigning;
  key_binding?: StubKeyBinding;

  // optional hint to simulate "finish/terminal" at verdict layer
  // (useful when events are not part of this driver input)
  terminal_present?: boolean;
};

export type VerdictStatus =
  | "VALID"
  | "INVALID"
  | "PENDING"
  | "AWAITING_EVIDENCE"
  | "NON_CLOSABLE"
  | "CONTESTED";

export type Verdict = {
  status: VerdictStatus;
  evidence?: StubEvidence;
  outcome?: StubOutcome;
  pointers?: StubPointers;
  mode?: "offline";
};

const ALLOWED_RECEIPT_KINDS = new Set(["R1", "R2", "ENV_ATTEST", "NON_CLOSABLE"]);

function receiptRank(kind: string): number | null {
  const m = /^R(\d+)$/.exec(kind);
  if (!m) return null;
  return parseInt(m[1], 10);
}

/**
 * Deterministic validation order (v1, minimal):
 * 1) RECEIPT_KIND_NOT_ALLOWED
 * 2) RECEIPT_LATE_AFTER_NON_CLOSABLE
 * 3) OUTCOME_BASIS_NOT_ALLOWED (ENV_ATTEST)
 * 4) SIGNATURE_INVALID
 * 5) KEY_BINDING_MISMATCH
 * 6) NON_EQUIVOCATION_VIOLATION
 * 7) RESULTSET_GATE (PENDING vs INVALID)
 * 8) OUTCOME_BASIS_CONFLICT => CONTESTED
 * 9) EVIDENCE_EVAL => VALID / AWAITING_EVIDENCE / NON_CLOSABLE
 */
function computeStatus(input: StubInput): VerdictStatus {
  const receipts = input.receipts ?? [];

  // 1) receipt kind whitelist
  for (const r of receipts) {
    if (!ALLOWED_RECEIPT_KINDS.has(r.kind)) return "INVALID";
  }

  // 2) no receipt after NON_CLOSABLE
  const idxNC = receipts.findIndex((r) => r.kind === "NON_CLOSABLE");
  if (idxNC >= 0 && idxNC < receipts.length - 1) return "INVALID";

  // 3) ENV_ATTEST cannot be outcome basis
  if (input.outcome?.basis === "ENV_ATTEST") return "INVALID";

  // 4) signature model v1 (pragmatic): signature == sha256(canonical_event utf8) hex
  if (input.signing) {
    const canonical = input.canonical_event ?? "";
    const want = sha256HexUtf8(canonical);
    if (input.signing.signature !== want) return "INVALID";
  }

  // 5) key binding must match signing
  if (input.key_binding && input.signing) {
    if (input.key_binding.public_key !== input.signing.public_key) return "INVALID";
  }

  // 6) non-equivocation: >1 distinct canonical event (canonicalized)
  if (input.canonical_events && input.canonical_events.length > 0) {
    const normalized: string[] = [];
    for (const s of input.canonical_events) {
      try {
        const obj = JSON.parse(s);
        normalized.push(canonicalizeJson(obj).canonical);
      } catch {
        // unparsable or non-canonicalizable => structural violation
        return "INVALID";
      }
    }
    const uniq = new Set(normalized);
    if (uniq.size > 1) return "INVALID";
  }

  // 7) ResultSet gate (async-first):
  // - if no resultset and no terminal => PENDING
  // - if no resultset but terminal signal present => INVALID
  const hasResultset = input.resultset_present === true;
  if (!hasResultset) {
    const terminal =
      input.terminal_present === true ||
      input.outcome !== undefined; // outcome present implies "trying to conclude"
    return terminal ? "INVALID" : "PENDING";
  }

  // From here: resultset present => we can evaluate
  const ev = input.evidence;
  if (!ev) return "INVALID";

  // 8) conflict between claimed basis and effective evidence => CONTESTED
  if (input.outcome && input.outcome.basis !== ev.effective) return "CONTESTED";

  // 9) evidence evaluation with degradation
  const eff = receiptRank(ev.effective);
  const req = receiptRank(ev.required);
  if (eff === null || req === null) return "INVALID";

  const nonClosableSignal = receipts.some((r) => r.kind === "NON_CLOSABLE");

  // If not qualified, we degrade (do NOT hard-fail by default)
  if (!ev.qualified) {
    return nonClosableSignal ? "NON_CLOSABLE" : "AWAITING_EVIDENCE";
  }

  if (eff >= req) return "VALID";
  return nonClosableSignal ? "NON_CLOSABLE" : "AWAITING_EVIDENCE";
}

export function verifyStub(input: StubInput, offline: boolean = false): Verdict {
  const status = computeStatus(input);

  // Keep deterministic field insertion order:
  // status, evidence, outcome, pointers, (mode)
  const verdict: Verdict = {
    status,
    evidence: input.evidence,
    outcome: input.outcome,
    pointers: input.pointers
  };

  if (offline) verdict.mode = "offline";
  return verdict;
}
