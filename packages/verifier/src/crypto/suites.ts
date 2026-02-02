export const CRYPTO_SUITES = {
  "IMMUVAv1-SHA256": {
    requires_public_key: false,
  },
  "IMMUVAv2-ED25519-SHA256": {
    requires_public_key: true,
  },
} as const;

export type CryptoSuiteName = keyof typeof CRYPTO_SUITES;
