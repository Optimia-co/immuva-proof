// Example: generate a proof with the Go SDK and verify it offline.
// The resulting proof.json can also be verified with the CLI:
//   immuva-proof verify /tmp/go-proof.json
package main

import (
	"encoding/json"
	"fmt"
	"os"

	immuva "immuva.dev/sdk/pkg"
)

func main() {
	// 1. Generate a key pair
	fmt.Println("→ Generating Ed25519 key pair...")
	keys, err := immuva.Keygen()
	if err != nil {
		fmt.Fprintf(os.Stderr, "keygen error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  public_key_hex:  %s\n", keys.PublicKeyHex)
	fmt.Printf("  key_id:          %s\n", keys.KeyID)

	// 2. Define an event
	event := map[string]any{
		"kind":      "PAYMENT_DECISION",
		"amount":    4200,
		"currency":  "EUR",
		"recipient": "vendor-42",
		"approved":  true,
	}

	// 3. Generate the proof
	fmt.Println("\n→ Generating proof...")
	proof, err := immuva.Prove(immuva.ProveOptions{
		Event:         event,
		PublicKeyHex:  keys.PublicKeyHex,
		PrivateKeyHex: keys.PrivateKeyHex,
		AgentID:       "go-payment-agent",
		ResultsetPresent: true,
		Evidence: &immuva.Evidence{
			Effective: "R1",
			Required:  "R1",
			Qualified: true,
		},
		Outcome: &immuva.Outcome{
			Value: "approve",
			Basis: "R1",
		},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "prove error: %v\n", err)
		os.Exit(1)
	}

	// 4. Verify the proof offline
	fmt.Println("\n→ Verifying proof offline...")
	verdict, err := immuva.Verify(proof)
	if err != nil {
		fmt.Fprintf(os.Stderr, "verify error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("  Status:      %s\n", verdict.Status)
	fmt.Printf("  ProofLevel:  %s\n", verdict.ProofLevel)

	// 5. Save proof to file
	outPath := "/tmp/go-proof.json"
	data, _ := json.MarshalIndent(proof, "", "  ")
	if err := os.WriteFile(outPath, data, 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\n→ Proof saved to %s\n", outPath)
	fmt.Printf("  Verify with CLI: immuva-proof verify %s\n", outPath)

	if verdict.Status != "VALID" {
		fmt.Fprintf(os.Stderr, "\nERROR: expected VALID, got %s\n", verdict.Status)
		os.Exit(1)
	}
	fmt.Println("\n✓ All checks passed — Go SDK is compatible with Immuva Protocol v2")
}
