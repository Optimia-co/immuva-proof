package pkg

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// ProveOptions holds the inputs required to generate a ProofBundle.
type ProveOptions struct {
	// The event to prove (any JSON-serializable value)
	Event map[string]any

	// Ed25519 key pair (hex-encoded)
	PublicKeyHex  string
	PrivateKeyHex string

	// Agent identifier (optional)
	AgentID string

	// Evidence about how the decision was reached
	Evidence *Evidence

	// The outcome of the event
	Outcome *Outcome

	// Whether the ResultSet is already present
	ResultsetPresent bool
}

// Evidence describes the regulatory basis for the decision.
type Evidence struct {
	Effective string `json:"effective"`
	Required  string `json:"required"`
	Qualified bool   `json:"qualified"`
}

// Outcome describes what was decided.
type Outcome struct {
	Value string `json:"value"`
	Basis string `json:"basis"`
}

// StubSigning matches @immuva/verifier StubSigning
type StubSigning struct {
	CryptoSuite string `json:"crypto_suite"`
	Signature   string `json:"signature"`
	PublicKey   string `json:"public_key"`
}

// StubKeyBinding matches @immuva/verifier StubKeyBinding
type StubKeyBinding struct {
	PublicKey string `json:"public_key"`
	KeyID     string `json:"key_id"`
	KeyStatus string `json:"key_status"`
}

// ProofBundle is the cryptographic proof produced by Prove().
// The structure matches @immuva/verifier StubInput exactly,
// ensuring 100% compatibility with @immuva/verifier and immuva-proof CLI.
type ProofBundle struct {
	// Canonical JSON string of the event (keys sorted lexicographically)
	CanonicalEvent string `json:"canonical_event"`

	// Cryptographic signature
	Signing StubSigning `json:"signing"`

	// Key binding — links the signature to the agent's public key
	KeyBinding StubKeyBinding `json:"key_binding"`

	// Evidence and outcome
	Evidence *Evidence `json:"evidence,omitempty"`
	Outcome  *Outcome  `json:"outcome,omitempty"`

	// Whether the ResultSet is present (false → PENDING verdict)
	ResultsetPresent bool `json:"resultset_present"`

	// Original event (for human inspection)
	Event map[string]any `json:"event,omitempty"`

	// Metadata
	CreatedAt string `json:"created_at,omitempty"`
	SDK       string `json:"sdk,omitempty"`
}

// Prove generates a cryptographic ProofBundle using the IMMUVAv2-ED25519-SHA256 algorithm.
//
// Algorithm (identical to @immuva/sdk session.ts proveOne):
//  1. canonical     = CanonicalJSON(event)              — keys sorted, minified
//  2. hashHex       = sha256HexUtf8(canonical)          — hex string
//  3. hashBytes     = hex.Decode(hashHex)               — 32 raw bytes
//  4. signature     = ed25519.Sign(privKey, hashBytes)  — sign the hash bytes
//  5. key_id        = sha256HexUtf8(publicKeyHex)       — sha256 of the HEX STRING
func Prove(opts ProveOptions) (*ProofBundle, error) {
	// 1. Canonical JSON
	canonical, err := CanonicalJSON(opts.Event)
	if err != nil {
		return nil, fmt.Errorf("prove: canonicalize event: %w", err)
	}

	// 2. sha256 of the canonical UTF-8 string → hex
	hashRaw := sha256.Sum256([]byte(canonical))
	// hashBytes is the raw 32 bytes we sign
	hashBytes := hashRaw[:]

	// 3. Decode private key (Go ed25519 private key = 64 bytes: seed || public)
	privBytes, err := hex.DecodeString(opts.PrivateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("prove: decode private key: %w", err)
	}
	if len(privBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("prove: private key must be %d bytes, got %d",
			ed25519.PrivateKeySize, len(privBytes))
	}

	// 4. Sign the 32 hash bytes directly
	sig := ed25519.Sign(ed25519.PrivateKey(privBytes), hashBytes)

	// 5. key_id = sha256(publicKeyHex as UTF-8 string)
	//    NOTE: this is sha256 of the HEX STRING, not sha256 of the raw key bytes.
	//    This matches sha256HexUtf8(publicKeyHex) in @immuva/canonical exactly.
	keyIDRaw := sha256.Sum256([]byte(opts.PublicKeyHex))
	keyID := hex.EncodeToString(keyIDRaw[:])

	return &ProofBundle{
		CanonicalEvent: canonical,
		Signing: StubSigning{
			CryptoSuite: "IMMUVAv2-ED25519-SHA256",
			Signature:   hex.EncodeToString(sig),
			PublicKey:   opts.PublicKeyHex,
		},
		KeyBinding: StubKeyBinding{
			PublicKey: opts.PublicKeyHex,
			KeyID:     keyID,
			KeyStatus: "ACTIVE",
		},
		Evidence:         opts.Evidence,
		Outcome:          opts.Outcome,
		ResultsetPresent: opts.ResultsetPresent,
		Event:            opts.Event,
		CreatedAt:        time.Now().UTC().Format(time.RFC3339),
		SDK:              "immuva-go/0.1.0",
	}, nil
}
