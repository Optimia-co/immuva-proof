import { buildDecisionEvent, PaymentRequest } from "./decision.js";

/**
 * We load the Immuva SDK at runtime.
 * This keeps the example aligned with real usage
 * (SDK is an executable artifact, not a library abstraction).
 */
async function loadSDK() {
  const sdk = await import("@immuva/sdk");
  return sdk;
}

export async function provePaymentDecision(req: PaymentRequest) {
  const sdk = await loadSDK();

  // 1) Build deterministic decision event
  const event = buildDecisionEvent(req);

  // 2) Generate agent keypair (normally persisted, not regenerated)
  const { public_key_hex, private_key_hex } = await sdk.keygen();

  // 3) Produce Immuva proof (v1.0.0 compatible)
  const proof = await sdk.prove({
    event,
    public_key_hex,
    private_key_hex,

    // semantic fields (interpreted by verifier)
    resultset_present: true,
    evidence: {
      effective: "R1",
      required: "R1",
      qualified: true
    },
    outcome: {
      value: event.decision,
      basis: "R1"
    }
  });

  return proof;
}

/**
 * CLI usage (manual test)
 */
if (process.argv[1] === new URL(import.meta.url).pathname) {
  const req: PaymentRequest = {
    payment_id: "pay_123",
    amount: 1200,
    currency: "EUR",
    risk_score: 0.42
  };

  provePaymentDecision(req).then((proof) => {
    console.log(JSON.stringify(proof, null, 2));
  });
}
