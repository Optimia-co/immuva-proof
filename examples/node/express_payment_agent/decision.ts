export type PaymentRequest = {
  payment_id: string;
  amount: number;
  currency: string;
  risk_score: number;
};

export type PaymentDecision = {
  decision: "approve" | "deny";
  reason: string;
  risk_score: number;
};

/**
 * Deterministic decision rule:
 * - approve if risk_score < 0.5
 * - deny otherwise
 *
 * IMPORTANT: no randomness, no timestamps, no external calls.
 */
export function decidePayment(req: PaymentRequest): PaymentDecision {
  if (typeof req.risk_score !== "number" || Number.isNaN(req.risk_score)) {
    return {
      decision: "deny",
      reason: "invalid_risk_score",
      risk_score: req.risk_score
    };
  }

  if (req.risk_score < 0.5) {
    return {
      decision: "approve",
      reason: "risk_below_threshold",
      risk_score: req.risk_score
    };
  }

  return {
    decision: "deny",
    reason: "risk_above_or_equal_threshold",
    risk_score: req.risk_score
  };
}

/**
 * The event payload that will be proven by Immuva.
 * Keep it explicit and stable (versioned).
 */
export function buildDecisionEvent(req: PaymentRequest) {
  const d = decidePayment(req);

  return {
    kind: "PAYMENT_DECISION",
    schema_version: "1.0.0",
    payment_id: req.payment_id,
    amount: req.amount,
    currency: req.currency,
    risk_score: req.risk_score,
    decision: d.decision,
    reason: d.reason
  };
}
