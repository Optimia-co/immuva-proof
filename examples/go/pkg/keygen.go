package pkg

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// KeyPair holds the Ed25519 public and private key as hex strings,
// plus the derived key_id.
type KeyPair struct {
	// PublicKeyHex: 32 bytes → 64 hex chars
	PublicKeyHex string
	// PrivateKeyHex: 64 bytes (seed || public) → 128 hex chars (Go stdlib convention)
	PrivateKeyHex string
	// KeyID: sha256(publicKeyHex as UTF-8 string) → 64 hex chars
	// Matches: sha256HexUtf8(publicKeyHex) in @immuva/canonical
	KeyID string
}

// Keygen generates a new Ed25519 key pair compatible with the Immuva Protocol v2.
func Keygen() (KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return KeyPair{}, fmt.Errorf("keygen: %w", err)
	}

	pubHex := hex.EncodeToString(pub)

	// key_id = sha256(publicKeyHex as UTF-8 string)
	// NOTE: this is sha256 of the HEX STRING, matching sha256HexUtf8() in TypeScript
	keyIDRaw := sha256.Sum256([]byte(pubHex))

	return KeyPair{
		PublicKeyHex:  pubHex,
		PrivateKeyHex: hex.EncodeToString(priv),
		KeyID:         hex.EncodeToString(keyIDRaw[:]),
	}, nil
}
