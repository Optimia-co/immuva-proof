/**
 * Canonical registry of supported cryptographic suites.
 * Normative: implementations MUST reject unknown suites.
 */

export type CryptoSuiteId =
  | "IMMUVAv1-SHA256"
  | "IMMUVAv2-ED25519-SHA256";

export type CryptoSuiteRule = {
  id: CryptoSuiteId;
  description: string;
  requires_public_key: boolean;
  signature_semantics: "hash-only" | "ed25519-sha256";
};

export const CRYPTO_SUITES: Record<CryptoSuiteId, CryptoSuiteRule> = {
  "IMMUVAv1-SHA256": {
    id: "IMMUVAv1-SHA256",
    description: "Legacy compatibility mode. signature == sha256(canonical_event).",
    requires_public_key: false,
    signature_semantics: "hash-only",
  },

  "IMMUVAv2-ED25519-SHA256": {
    id: "IMMUVAv2-ED25519-SHA256",
    description: "Ed25519 signature over sha256(canonical_event).",
    requires_public_key: true,
    signature_semantics: "ed25519-sha256",
  },
} as const;
