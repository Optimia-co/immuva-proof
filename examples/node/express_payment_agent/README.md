# Express Payment Agent — Immuva Proof Example

This example demonstrates how to use **Immuva Proof v1.0.0**
to make a **verifiable payment decision** by an autonomous agent.

The goal is to prove:
> “This agent approved (or denied) this payment, at this time,
> under these exact inputs — and this proof can be verified offline forever.”

---

## Scenario

An AI payment agent receives a payment request:

```json
{
  "payment_id": "pay_123",
  "amount": 1200,
  "currency": "EUR",
  "risk_score": 0.42
}
The agent applies a deterministic rule:

approve if risk_score < 0.5

deny otherwise

Flow (strict order)
Decision

The agent computes a decision from inputs

Canonicalization

The decision payload is canonicalized (JCS)

Proof generation

The canonical payload is signed (Ed25519)

A proof bundle is produced

Verification

Anyone can verify the proof offline

Any modification invalidates the proof

Files
arduino
Copier le code
decision.ts   # deterministic decision logic
prove.ts      # proof generation (Immuva SDK)
verify.ts     # offline verification
execute.ts    # demo runner
Security Properties
Deterministic verification

No trusted third party

Offline verifiable

Cryptographically bound to the agent key

Non-equivocation guaranteed

What This Example Is NOT
Not a blockchain

Not logging

Not audit-by-trust

Not replayable with modified data

Expected Outcome
Valid proof → VALID

Modified input → INVALID

Modified signature → INVALID

This example is normative and compatible with
Immuva Proof v1.0.0 forever.

