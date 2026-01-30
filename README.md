# Immuva Proof

**Immuva Proof** is a cryptographic proof standard designed to make autonomous AI actions
**verifiable, auditable, and non-repudiable**.

It transforms critical AI decisions into cryptographic evidence.

---

## What problem does Immuva solve?

Autonomous AI systems increasingly:
- execute irreversible actions
- operate without human oversight
- make decisions subject to audit, regulation, or dispute

Traditional logs are **not proofs**:
- they can be modified
- they rely on trust
- they are not independently verifiable

**Immuva replaces trust with cryptographic evidence.**

---

## Core principles

- **Verification-first**  
  Proofs can be verified independently, without access to Immuva.

- **Zero-trust identity**  
  Actions are signed by the agent’s own cryptographic identity.

- **Audit-ready**  
  Proofs are deterministic, timestamped, and non-repudiable.

- **No data leakage**  
  Only cryptographic commitments (hashes) are recorded.

---

## What is an Immuva Proof?

An Immuva proof is a cryptographic receipt that attests:

- who acted (cryptographic identity)
- what action was taken
- when it happened
- with which contextual commitment
- in which immutable sequence

Proofs are bundled into a deterministic format called a **ProofBundle**.

---

## ProofBundle format

A ProofBundle is a folder or deterministic zip containing:

- `events.jsonl` — append-only chained events
- `hashes.json` — file integrity
- `signature.json` — cryptographic seal and proof level
- optional artifacts (redaction reports, metadata)

ProofBundles can be verified **offline**, without Immuva infrastructure.

---

## Proof levels

Immuva supports multiple proof assurance levels:

| Level | Guarantee | Typical usage |
|------|----------|---------------|
| VALID | Integrity & immutability | Internal logs |
| KEY_PROTECTED | Signature from HSM / enclave | Security audits |
| TIME_ANCHORED | Independent timestamp | Legal precedence |
| CERTIFIED_IMMUVA | Identity certified by authority | Regulatory & contractual proof |

---

## What Immuva does NOT do

Immuva does not:
- validate business logic
- prevent incorrect decisions
- judge actions
- replace human audits

**Immuva provides proof, not opinions.**

---

## Verification

Verification is always free.

Proofs can be verified using:
- the open-source CLI
- third-party auditors
- automated compliance pipelines
- 
## Specification

The formal Immuva Proof specification is defined here:
https://github.com/Optimia-co/immuva-proof-spec

