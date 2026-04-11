import { fsRegistryProvider } from "./registry/provider";
import type { RegistryProvider } from "./registry/provider";
import { sha256HexUtf8, canonicalizeJson } from "../../canonical/dist/index.js";
import { createHash } from "node:crypto";
import { verifyEd25519Signature } from "./crypto/ed25519.js";
import { CRYPTO_SUITES } from "./crypto/suites.js";
import { uniqAndSortViolations } from "./policy-violations.js";
import { rank } from "./proof-levels.js";


type ViolationCode =
  | "KEY_ID_REQUIRED"
  | "KEY_ID_MISMATCH"
  | "KEY_REVOKED"
  | "KEY_ROTATED"

  | "REGISTRY_UNAVAILABLE"
  | "RECEIPT_KIND_NOT_ALLOWED"
  | "RECEIPT_LATE_AFTER_NON_CLOSABLE"
  | "OUTCOME_BASIS_NOT_ALLOWED"
  | "SIGNATURE_INVALID"
  | "KEY_BINDING_MISMATCH"
  | "NON_EQUIVOCATION_VIOLATION"
  | "RESULTSET_MISSING"
  | "RESULTSET_MISSING_BUT_TERMINAL"
  | "EVIDENCE_MISSING"
  | "EVIDENCE_NOT_QUALIFIED"
  | "EVIDENCE_REQUIRED_NOT_MET"
  | "OUTCOME_BASIS_CONFLICT"
  | "NON_CLOSABLE_SIGNAL";


type JSONValue =
  | null
  | boolean
  | number
  | string
  | JSONValue[]
  | { [k: string]: JSONValue };

export type VerifyContext = {
  proof_levels?: boolean;
  min_proof_level?: string;
  require_key_bound?: boolean;
  require_time_anchor?: boolean;
  require_transparency_log?: boolean;

  // Signed policy enforcement (A15+)
  policy?: VerifiedPolicy;

  // Registry resolution (SDK/API)
  registry_provider?: RegistryProvider;
  spec_root?: string;
};

// Opaque verified policy (validated upstream)
export type VerifiedPolicy = {
  readonly policy_id?: string;
  readonly signature?: string;
  readonly trust_root?: string;
};


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
  crypto_suite?: string;
  public_key?: string;
  signature: string; // hex(sha256(canonical_event)) for now
};

export type StubKeyBinding = {
  key_id?: string;
  public_key?: string;
  key_status?: "ACTIVE" | "ROTATED" | "REVOKED";
  /** ISO 8601 — when the key was rotated (key is no longer valid for new proofs) */
  rotated_at?: string;
  /** ISO 8601 — when the key was revoked (all proofs using it are invalid) */
  revoked_at?: string;
};

export type StubInput = {
  // T-min gate
  resultset_present?: boolean;

  evidence?: StubEvidence;
  outcome?: StubOutcome;
  pointers?: StubPointers;

  receipts?: StubReceipt[];

  canonical_event?: string;
  canonical_events?: string[];

  signing?: StubSigning;
  key_binding?: StubKeyBinding;

  // Policy / proof extensions (opt-in)
  time_anchor?: any;
  transparency_log?: any;

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

  // policy extensions (optional)
  proof_level?: string;
  violations?: ViolationCode[];
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
function computeStatus(input: StubInput): { status: VerdictStatus; violations: ViolationCode[] } {
  const violations: ViolationCode[] = [];
  const ret = (status: VerdictStatus) => ({ status, violations });

  // 0) crypto suite whitelist (IMMUVAv1-SHA256 | IMMUVAv2-ED25519-SHA256)
  //    Any suite name that is absent from CRYPTO_SUITES is rejected immediately —
  //    no silent fallback to v1 is allowed.
  if (input.signing) {
    const suiteName = input.signing.crypto_suite;
    if (!suiteName || !(suiteName in CRYPTO_SUITES)) {
      return ret("INVALID");
    }
    const suite = suiteName as keyof typeof CRYPTO_SUITES;
    const rule = CRYPTO_SUITES[suite];
    if (rule.requires_public_key && !input.signing.public_key) {
      return ret("INVALID");
    }
  }

  const receipts = input.receipts ?? [];

  // 1) receipt kind whitelist
  for (const r of receipts) {
    if (!ALLOWED_RECEIPT_KINDS.has(r.kind)) return ret("INVALID");
  }

  // 2) no receipt after NON_CLOSABLE
  const idxNC = receipts.findIndex((r) => r.kind === "NON_CLOSABLE");
  if (idxNC >= 0 && idxNC < receipts.length - 1) return ret("INVALID");

  // 3) ENV_ATTEST cannot be outcome basis
  if (input.outcome?.basis === "ENV_ATTEST") return ret("INVALID");

  // 4) signature validation (v1 hash-only OR v2 ed25519)
  if (input.signing) {
    const canonical = input.canonical_event ?? "";

    // v2: Ed25519 over sha256(canonical_event)
    if (input.signing.crypto_suite === "IMMUVAv2-ED25519-SHA256") {
      if (!input.signing.public_key) return ret("INVALID");
      const ok = verifyEd25519Signature(
        canonical,
        input.signing.signature,
        input.signing.public_key
      );
      if (!ok) return ret("INVALID");
    }

    // v1 (default): signature == sha256(canonical_event) hex
    else {
      const want = sha256HexUtf8(canonical);
      if (input.signing.signature !== want) return ret("INVALID");
    }
  }

  // 5) key binding (v1 + v2)
  if (input.signing && input.key_binding) {
    if (input.signing.public_key !== input.key_binding.public_key) {
      return ret("INVALID");
    }
  }

  // 5b) v2-only key lifecycle rules
  if (input.signing?.crypto_suite === "IMMUVAv2-ED25519-SHA256") {
    const pub = input.signing.public_key;
    if (!pub) return ret("INVALID");

    const kb = input.key_binding;
    if (!kb) return ret("INVALID");

    // key_id MUST equal sha256(public_key_hex) — not sha256(canonical_event)
    if (!kb.key_id) return ret("INVALID");
    const wantKeyId = sha256HexUtf8(pub);
    if (kb.key_id !== wantKeyId) return ret("INVALID");

    // Revoked keys invalidate all proofs signed with them
    if (kb.key_status === "REVOKED" || kb.revoked_at) {
      violations.push("KEY_REVOKED");
      return ret("INVALID");
    }

    // Rotated keys cannot sign new proofs; if the proof carries a
    // time_anchor we compare timestamps — otherwise we reject conservatively.
    if (kb.key_status === "ROTATED") {
      violations.push("KEY_ROTATED");
      return ret("INVALID");
    }
    if (kb.rotated_at) {
      // If a time_anchor is present, the proof timestamp must be BEFORE rotation
      const proofTs: string | undefined = input.time_anchor?.timestamp ?? input.time_anchor?.ts;
      if (!proofTs || new Date(proofTs) >= new Date(kb.rotated_at)) {
        violations.push("KEY_ROTATED");
        return ret("INVALID");
      }
    }
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
        return ret("INVALID");
      }
    }
    const uniq = new Set(normalized);
    if (uniq.size > 1) return ret("INVALID");
  }

  // 7) ResultSet gate (async-first):
  // - if no resultset and no terminal => PENDING
  // - if no resultset but terminal signal present => INVALID
  const hasResultset = input.resultset_present === true;
  if (!hasResultset) {
    const terminal =
      input.terminal_present === true ||
      input.outcome !== undefined; // outcome present implies "trying to conclude"
    return ret(terminal ? "INVALID" : "PENDING");
  }

  // From here: resultset present => we can evaluate
  const ev = input.evidence;
  if (!ev) return ret("INVALID");

  // 8) conflict between claimed basis and effective evidence => CONTESTED
  if (input.outcome && input.outcome.basis !== ev.effective) return ret("CONTESTED");

  // 9) evidence evaluation with degradation
  const eff = receiptRank(ev.effective);
  const req = receiptRank(ev.required);
  if (eff === null || req === null) return ret("INVALID");

  const nonClosableSignal = receipts.some((r) => r.kind === "NON_CLOSABLE");

  // If not qualified, we degrade (do NOT hard-fail by default)
  if (!ev.qualified) {
    return ret(nonClosableSignal ? "NON_CLOSABLE" : "AWAITING_EVIDENCE");
  }

  if (eff >= req) return ret("VALID");
  return ret(nonClosableSignal ? "NON_CLOSABLE" : "AWAITING_EVIDENCE");
}

const computeProofLevel = (input: StubInput) => {
  if (input.transparency_log) return "TRANSPARENCY_LOGGED";
  if (input.time_anchor) return "TIME_ANCHORED";
  if (input.key_binding) return "KEY_BOUND";
  return "BASIC";
};

export function verifyStub(input: StubInput, offline: boolean = false, ctx?: VerifyContext): Verdict {
  const { status } = computeStatus(input);

  // Keep deterministic field insertion order:
  // status, evidence, outcome, pointers, (mode)
  const verdict: Verdict = {
    status,
    evidence: input.evidence,
    outcome: input.outcome,
    pointers: input.pointers
  };

  if (offline) verdict.mode = "offline";
  
  // Policy composition (normative)
  if (verdict.status === "VALID" && ctx) {

    // Compute proof level ONLY if needed
    const needsPL = !!(ctx.proof_levels || ctx.min_proof_level);
    const gotPL = needsPL ? computeProofLevel(input) : undefined;

    // Attach proof_level ONLY if requested
    if (ctx.proof_levels && gotPL) {
      verdict.proof_level = gotPL;
    }

    // A9.2 — min_proof_level OVERRIDES all require_* checks
    if (ctx.min_proof_level && gotPL) {
      if (rank(gotPL as any) < rank(ctx.min_proof_level as any)) {
        return {
          status: "INVALID",
          violations: uniqAndSortViolations([{ code: "MIN_PROOF_LEVEL_NOT_MET" }])
        } as any;
      }
    }

    // require_* constraints (ONLY if min_proof_level passed)
    const vios: { code: string }[] = [];

    if (ctx.require_key_bound && !input.key_binding) {
      vios.push({ code: "KEY_BINDING_REQUIRED" });
    }

    if (ctx.require_time_anchor && !input.time_anchor) {
      vios.push({ code: "TIME_ANCHOR_REQUIRED" });
    }

    if (ctx.require_transparency_log && !input.transparency_log) {
      vios.push({ code: "TRANSPARENCY_LOG_REQUIRED" });
    }

    if (vios.length > 0) {
      return { status: "INVALID", violations: uniqAndSortViolations(vios) } as any;
    }
  }

  return verdict;

}

import { loadViolationRegistry } from "./registry/violations";

export type VerdictWithDetails = Omit<Verdict, "violations"> & {
  violations: {
    code: ViolationCode;
    severity: string;
  }[];
};

export function verifyWithDetails(
  input: StubInput,
  offline: boolean = false,
  ctx?: VerifyContext
): VerdictWithDetails {
  const { status, violations } = computeStatus(input);
  const provider =
  (ctx && ctx.registry_provider)
    ? ctx.registry_provider
    : (ctx && ctx.spec_root)
      ? fsRegistryProvider(ctx.spec_root)
      : process.env.IMMUVA_SPEC_ROOT
        ? fsRegistryProvider(process.env.IMMUVA_SPEC_ROOT)
        : null;

if (!provider) {
  return {
    status: "INVALID",
    mode: offline ? "offline" : undefined,
    violations: [{ code: "REGISTRY_UNAVAILABLE", severity: "invalid" }]
  };
}

const reg = loadViolationRegistry(provider);

  return {
    status,
    evidence: input.evidence,
    outcome: input.outcome,
    pointers: input.pointers,
    mode: offline ? "offline" : undefined,
    violations: violations.map((v) => ({
      code: v,
      severity: reg.get(v)?.severity ?? "invalid"
    }))
  };
}

export type VerdictExplanationStep = {
  step: number;
  rule: string;
  outcome: "pass" | "fail";
  violations?: ViolationCode[];
};

export type VerdictExplanation = {
  steps: VerdictExplanationStep[];
};

export function explainVerdict(input: StubInput): VerdictExplanation {
  const steps: VerdictExplanationStep[] = [];

  const receipts = input.receipts ?? [];

  // 1) RECEIPT_KIND_NOT_ALLOWED
  const badKinds = receipts.filter(r => !ALLOWED_RECEIPT_KINDS.has(r.kind));
  steps.push({
    step: 1,
    rule: "RECEIPT_KIND_NOT_ALLOWED",
    outcome: badKinds.length === 0 ? "pass" : "fail",
    violations: badKinds.length ? ["RECEIPT_KIND_NOT_ALLOWED"] : undefined
  });

  // 2) RECEIPT_LATE_AFTER_NON_CLOSABLE
  const idxNC = receipts.findIndex(r => r.kind === "NON_CLOSABLE");
  const late = idxNC >= 0 && idxNC < receipts.length - 1;
  steps.push({
    step: 2,
    rule: "RECEIPT_LATE_AFTER_NON_CLOSABLE",
    outcome: late ? "fail" : "pass",
    violations: late ? ["RECEIPT_LATE_AFTER_NON_CLOSABLE"] : undefined
  });

  // 3) OUTCOME_BASIS_NOT_ALLOWED
  const badBasis = input.outcome?.basis === "ENV_ATTEST";
  steps.push({
    step: 3,
    rule: "OUTCOME_BASIS_NOT_ALLOWED",
    outcome: badBasis ? "fail" : "pass",
    violations: badBasis ? ["OUTCOME_BASIS_NOT_ALLOWED"] : undefined
  });

  // 4) SIGNATURE_INVALID
  if (input.signing) {
    let ok: boolean;
    if (input.signing.crypto_suite === "IMMUVAv2-ED25519-SHA256") {
      // v2: Ed25519 signature verified against sha256(canonical_event)
      ok = input.signing.public_key
        ? verifyEd25519Signature(
            input.canonical_event ?? "",
            input.signing.signature,
            input.signing.public_key
          )
        : false;
    } else {
      // v1: signature == sha256(canonical_event) hex
      const want = sha256HexUtf8(input.canonical_event ?? "");
      ok = input.signing.signature === want;
    }
    steps.push({
      step: 4,
      rule: "SIGNATURE_INVALID",
      outcome: ok ? "pass" : "fail",
      violations: ok ? undefined : ["SIGNATURE_INVALID"]
    });
  }

  // 5) KEY_BINDING_MISMATCH
  if (input.signing && input.key_binding) {
    const ok = input.signing.public_key === input.key_binding.public_key;
    steps.push({
      step: 5,
      rule: "KEY_BINDING_MISMATCH",
      outcome: ok ? "pass" : "fail",
      violations: ok ? undefined : ["KEY_BINDING_MISMATCH"]
    });
  }

  // 6) NON_EQUIVOCATION_VIOLATION
  if (input.canonical_events && input.canonical_events.length > 1) {
    const normalized: string[] = [];
    let structuralError = false;
    for (const s of input.canonical_events) {
      try {
        const obj = JSON.parse(s);
        normalized.push(canonicalizeJson(obj).canonical);
      } catch {
        structuralError = true;
        break;
      }
    }
    const equivocating = structuralError || new Set(normalized).size > 1;
    steps.push({
      step: 6,
      rule: "NON_EQUIVOCATION_VIOLATION",
      outcome: equivocating ? "fail" : "pass",
      violations: equivocating ? ["NON_EQUIVOCATION_VIOLATION"] : undefined
    });
  }

  // 7) RESULTSET_MISSING / PENDING
  const hasResultset = input.resultset_present === true;
  const terminal = input.terminal_present === true || input.outcome !== undefined;
  if (!hasResultset) {
    steps.push({
      step: 7,
      rule: "RESULTSET_MISSING",
      outcome: "fail",
      violations: terminal ? ["RESULTSET_MISSING_BUT_TERMINAL"] : ["RESULTSET_MISSING"]
    });
  } else {
    steps.push({ step: 7, rule: "RESULTSET_MISSING", outcome: "pass" });
  }

  // 8) OUTCOME_BASIS_CONFLICT / CONTESTED
  if (hasResultset && input.evidence && input.outcome) {
    const conflict = input.outcome.basis !== input.evidence.effective;
    steps.push({
      step: 8,
      rule: "OUTCOME_BASIS_CONFLICT",
      outcome: conflict ? "fail" : "pass",
      violations: conflict ? ["OUTCOME_BASIS_CONFLICT"] : undefined
    });
  }

  // 9) EVIDENCE_NOT_QUALIFIED / AWAITING_EVIDENCE
  if (hasResultset && input.evidence) {
    const qualified = input.evidence.qualified;
    steps.push({
      step: 9,
      rule: "EVIDENCE_NOT_QUALIFIED",
      outcome: qualified ? "pass" : "fail",
      violations: qualified ? undefined : ["EVIDENCE_NOT_QUALIFIED"]
    });
  }

  return { steps };
}

export function verifyExplained(
  input: StubInput,
  offline: boolean = false
): VerdictWithDetails & { explanation: VerdictExplanation } {
  return {
    ...verifyWithDetails(input, offline, undefined),
    explanation: explainVerdict(input)
  };
}
