# Immuva Protocol

[![npm](https://img.shields.io/npm/v/@immuva/sdk?label=%40immuva%2Fsdk)](https://www.npmjs.com/package/@immuva/sdk)
[![npm](https://img.shields.io/npm/v/@immuva/verifier?label=%40immuva%2Fverifier)](https://www.npmjs.com/package/@immuva/verifier)
![Conformance](https://img.shields.io/badge/conformance-20%2F20-brightgreen)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

---

## Immuva doesn't prevent mistakes. It prevents denial.

Immuva is the cryptographic proof layer for autonomous AI actions. Every action your AI agent takes becomes a tamper-proof, offline-verifiable cryptographic proof.

---

## OpenBox governs. Immuva proves.

OpenBox controls AI agents at runtime. Immuva proves what happened after — offline, forever, without depending on any server. They are complementary layers, not competitors.

---

## Quick Start

```bash
npm install @immuva/sdk
```

```ts
import { prove, keygen } from '@immuva/sdk'
import * as fs from 'fs'

// Generate agent keys (once)
const keys = await keygen({ out: './agent-keys' })

// Load keys
const private_key_hex = fs.readFileSync('./agent-keys.key', 'utf8').trim()
const public_key_hex  = fs.readFileSync('./agent-keys.pub', 'utf8').trim()

// Prove an action
const proof = await prove({
  event: {
    kind: 'PAYMENT_DECISION',
    amount: 4200,
    currency: 'EUR',
    decision: 'approve'
  },
  public_key_hex,
  private_key_hex,
  resultset_present: true,
  evidence: { effective: 'R1', required: 'R1', qualified: true },
  outcome: { value: 'approve', basis: 'R1' }
})

fs.writeFileSync('proof.json', JSON.stringify(proof, null, 2))

// Verify
// $ immuva-proof verify proof.json
// → { "status": "VALID", "proof_level": "KEY_BOUND" }
```

---

## Verify offline

```bash
$ immuva-proof verify proof.json
→ { "status": "VALID", "proof_level": "KEY_BOUND" }

$ immuva-proof verify proof.json --proof-levels
$ immuva-proof verify proof.json --offline
$ immuva-proof verify proof.json --format json
```

---

## High-frequency mode (SessionBundle)

For high-throughput environments — N actions, one Merkle tree, one signature:

```ts
import { proveSession } from '@immuva/sdk'

const bundle = await proveSession(events, public_key_hex, private_key_hex)
// bundle.merkle_root       — Merkle root of all actions
// bundle.session_signature — single Ed25519 signature
// bundle.proofs[]          — each action individually verifiable
```

---

## Agent Trust Tier

```ts
import { computeAgentTrust } from '@immuva/sdk'

const trust = computeAgentTrust(proofHistory)
// { score: 87, level: 'TRUSTED', consecutive_valid: 43 }
// Levels: NEW → LEARNING → TRUSTED → VERIFIED
```

---

## LangChain integration (coming soon)

`@immuva/langchain` — in development.  
Every LangChain tool call will automatically generate a ProofBundle.

---

## REST API

Base URL: `https://immuva-api.fly.dev`

```
GET  /health      → { "status": "ok" }
POST /v1/verify   → { "status": "VALID", "proof_level": "KEY_BOUND" }
POST /v1/proofs   → ProofBundle
```

---

## Packages

| Package | Version | Description |
|---|---|---|
| `@immuva/sdk` | 0.2.0 | Public SDK — prove, verify, keygen, proveSession, computeAgentTrust |
| `@immuva/verifier` | 1.0.4 | Core verifier — 9-step deterministic pipeline |
| `@immuva/cli` | 1.0.3 | CLI — `immuva-proof verify proof.json` |
| `@immuva/canonical` | 1.0.0 | Deterministic JSON canonicalization |
| `@immuva/protocol` | 1.0.0 | Types and constants |
| `@immuva/fsm` | 1.0.0 | FSM validation — `validateFSM()` |
| `@immuva/evidence` | 1.0.0 | Evidence validation |

---

## Conformance

```
✅ 20/20 conformance tests
- core    : 17/17
- tl      :  1/1
- policies:  2/2
```

```bash
pnpm run check:all
```

---

## The 4 Proof Levels

| Level | What it adds |
|---|---|
| `BASIC` | Hash + signature only |
| `KEY_BOUND` | + public key binding |
| `TIME_ANCHORED` | + cryptographic timestamp |
| `TRANSPARENCY_LOGGED` | + public append-only log |

---

## Why Immuva

| Feature | Classic log | Immuva ProofBundle |
|---|---|---|
| Tamper detection | ❌ | ✅ |
| Offline verification | ❌ | ✅ |
| No server dependency | ❌ | ✅ |
| Open specification | ❌ | ✅ |
| Zero sensitive data stored | ❌ | ✅ |
| Legal probative value | ⚠️ | ✅ |

---

## Protocol

- Crypto suite: `IMMUVAv2-ED25519-SHA256`
- Spec: frozen at v1.0.0 — never changes
- Proofs generated today verifiable in 20 years

---

## License

MIT — verification is and will always be free.
