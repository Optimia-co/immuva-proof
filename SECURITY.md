# Security Policy

## Reporting vulnerabilities

If you discover a security vulnerability in Immuva Proof, please report it responsibly.

Contact:
security@immuva.com

Do not open public issues for security-sensitive matters.

---

## Threat model

Immuva Proof is designed to mitigate:
- post-hoc log tampering
- denial of responsibility for autonomous actions
- unverifiable AI decisions
- absence of cryptographic audit trails

It is not designed to:
- prevent incorrect decisions
- enforce agent behavior
- detect omitted actions

---

## Cryptographic assumptions

- Ed25519 signatures
- SHA-256 hashing
- Deterministic bundle construction
- Offline-verifiable proofs

Security relies on correct key management by integrators.

---

## Revocation

Compromised signing keys can be revoked via certified revocation lists (CRL).
Revoked keys invalidate future proofs signed with that identity.
