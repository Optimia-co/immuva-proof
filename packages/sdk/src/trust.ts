/**
 * @immuva/sdk — Agent Trust Tier
 *
 * Computes a trust score and level for an agent based on its proof history.
 *
 * Scoring model:
 *   consecutive_valid  = number of consecutive VALID verdicts from the end
 *   valid_ratio        = total_valid / total_proofs  (0–1)
 *   score              = min(100, consecutive_valid * 2 + valid_ratio * 20)
 *
 * Levels:
 *   NEW      : score < 20   (insufficient history or too many failures)
 *   LEARNING : score 20–49
 *   TRUSTED  : score 50–79
 *   VERIFIED : score >= 80  (typically 100+ consecutive VALID proofs)
 */

import { sha256HexUtf8 } from "../../canonical/dist/index.js";

export type AgentTrustLevel = "NEW" | "LEARNING" | "TRUSTED" | "VERIFIED";

export type AgentTrustScore = {
  /** sha256(public_key_hex) — stable identifier for the agent keypair. */
  agent_key_id: string;
  /** Composite trust score, 0–100. */
  score: number;
  /** Qualitative tier derived from score. */
  level: AgentTrustLevel;
  /** Count of unbroken VALID verdicts from the most recent proof backwards. */
  consecutive_valid: number;
  /** Total proofs evaluated. */
  total_proofs: number;
  /** Total non-VALID verdicts (INVALID, PENDING, AWAITING_EVIDENCE, etc.). */
  total_invalid: number;
  /** ISO 8601 timestamp of computation. */
  last_computed_at: string;
};

type ProofRecord = {
  verdict: string;
  key_binding?: { key_id?: string };
};

/**
 * Compute the trust score for an agent from its proof history.
 *
 * @param proofs  Ordered proof records (oldest first), each with a verdict
 *                string and an optional key_binding.key_id.
 * @returns AgentTrustScore
 */
export function computeAgentTrust(proofs: ProofRecord[]): AgentTrustScore {
  const total_proofs = proofs.length;

  // Derive agent_key_id from the first proof that carries one, or fall back
  // to a stable hash of a sentinel value.
  const rawKeyId =
    proofs.find(p => p.key_binding?.key_id)?.key_binding?.key_id ?? "";
  const agent_key_id = rawKeyId || sha256HexUtf8("unknown-agent");

  if (total_proofs === 0) {
    return {
      agent_key_id,
      score: 0,
      level: "NEW",
      consecutive_valid: 0,
      total_proofs: 0,
      total_invalid: 0,
      last_computed_at: new Date().toISOString(),
    };
  }

  // Count consecutive VALID from the end (most recent backwards)
  let consecutive_valid = 0;
  for (let i = proofs.length - 1; i >= 0; i--) {
    if (proofs[i].verdict === "VALID") {
      consecutive_valid++;
    } else {
      break;
    }
  }

  const total_valid = proofs.filter(p => p.verdict === "VALID").length;
  const total_invalid = total_proofs - total_valid;
  const valid_ratio = total_valid / total_proofs;

  // score = min(100, consecutive_valid * 2 + valid_ratio * 20)
  const raw = consecutive_valid * 2 + valid_ratio * 20;
  const score = Math.min(100, Math.round(raw));

  const level: AgentTrustLevel =
    score >= 80 ? "VERIFIED"
    : score >= 50 ? "TRUSTED"
    : score >= 20 ? "LEARNING"
    : "NEW";

  return {
    agent_key_id,
    score,
    level,
    consecutive_valid,
    total_proofs,
    total_invalid,
    last_computed_at: new Date().toISOString(),
  };
}
