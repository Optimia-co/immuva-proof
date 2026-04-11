package pkg

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// VerdictStatus represents the verification result.
type VerdictStatus string

const (
	VerdictVALID             VerdictStatus = "VALID"
	VerdictINVALID           VerdictStatus = "INVALID"
	VerdictPENDING           VerdictStatus = "PENDING"
	VerdictAWAITING_EVIDENCE VerdictStatus = "AWAITING_EVIDENCE"
	VerdictCONTESTED         VerdictStatus = "CONTESTED"
	VerdictNON_CLOSABLE      VerdictStatus = "NON_CLOSABLE"
)

// Verdict is the result of verifying a ProofBundle.
type Verdict struct {
	Status     VerdictStatus `json:"status"`
	ProofLevel string        `json:"proof_level,omitempty"`
	Violations []string      `json:"violations,omitempty"`
}

// Verify performs offline cryptographic verification of a ProofBundle.
// Mirrors the @immuva/verifier computeStatus() function for IMMUVAv2.
func Verify(bundle *ProofBundle) (*Verdict, error) {
	// 1. Check crypto suite
	if bundle.Signing.CryptoSuite != "IMMUVAv2-ED25519-SHA256" {
		return &Verdict{
			Status:     VerdictINVALID,
			Violations: []string{fmt.Sprintf("unknown crypto_suite: %q", bundle.Signing.CryptoSuite)},
		}, nil
	}

	// 2. Recompute canonical JSON from event
	canonical, err := CanonicalJSON(bundle.Event)
	if err != nil {
		return nil, fmt.Errorf("verify: canonicalize event: %w", err)
	}

	// Verify canonical matches stored canonical_event
	if bundle.CanonicalEvent != "" && canonical != bundle.CanonicalEvent {
		return &Verdict{
			Status:     VerdictINVALID,
			Violations: []string{"canonical_event mismatch"},
		}, nil
	}

	// Use stored canonical_event if available (may have been produced by another SDK)
	effectiveCanonical := bundle.CanonicalEvent
	if effectiveCanonical == "" {
		effectiveCanonical = canonical
	}

	// 3. Compute sha256(canonical) → raw bytes
	hashRaw := sha256.Sum256([]byte(effectiveCanonical))

	// 4. Verify Ed25519 signature
	pubBytes, err := hex.DecodeString(bundle.Signing.PublicKey)
	if err != nil {
		return &Verdict{Status: VerdictINVALID, Violations: []string{"invalid public_key encoding"}}, nil
	}
	sigBytes, err := hex.DecodeString(bundle.Signing.Signature)
	if err != nil {
		return &Verdict{Status: VerdictINVALID, Violations: []string{"invalid signature encoding"}}, nil
	}

	if !ed25519.Verify(pubBytes, hashRaw[:], sigBytes) {
		return &Verdict{
			Status:     VerdictINVALID,
			Violations: []string{"signature verification failed"},
		}, nil
	}

	// 5a. key_binding.public_key must match signing.public_key
	if bundle.KeyBinding.PublicKey != "" && bundle.KeyBinding.PublicKey != bundle.Signing.PublicKey {
		return &Verdict{
			Status:     VerdictINVALID,
			Violations: []string{"key_binding.public_key does not match signing.public_key"},
		}, nil
	}

	// 5b. key_id MUST equal sha256(publicKeyHex as UTF-8 string)
	if bundle.KeyBinding.KeyID != "" {
		wantKeyID := sha256.Sum256([]byte(bundle.Signing.PublicKey))
		if bundle.KeyBinding.KeyID != hex.EncodeToString(wantKeyID[:]) {
			return &Verdict{
				Status:     VerdictINVALID,
				Violations: []string{"key_id does not match sha256(public_key_hex)"},
			}, nil
		}
	}

	// 5c. Key lifecycle
	if bundle.KeyBinding.KeyStatus == "REVOKED" {
		return &Verdict{
			Status:     VerdictINVALID,
			Violations: []string{"KEY_REVOKED"},
		}, nil
	}
	if bundle.KeyBinding.KeyStatus == "ROTATED" {
		return &Verdict{
			Status:     VerdictINVALID,
			Violations: []string{"KEY_ROTATED"},
		}, nil
	}

	// 6. Evidence check
	if bundle.Evidence != nil && !bundle.Evidence.Qualified {
		return &Verdict{
			Status:     VerdictAWAITING_EVIDENCE,
			ProofLevel: "KEY_BOUND",
			Violations: []string{"evidence.qualified is false"},
		}, nil
	}

	// 7. ResultSet gate → PENDING if not present
	if !bundle.ResultsetPresent {
		return &Verdict{Status: VerdictPENDING, ProofLevel: "KEY_BOUND"}, nil
	}

	return &Verdict{Status: VerdictVALID, ProofLevel: "KEY_BOUND"}, nil
}
