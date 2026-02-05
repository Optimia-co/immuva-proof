import * as ed25519 from "@noble/ed25519";
import { randomBytes } from "node:crypto";
import fs from "node:fs";

export async function keygen(opts: { out?: string } = {}) {
  const seed = randomBytes(32);
  const privHex = Buffer.from(seed).toString("hex");
  const pubHex = Buffer.from(await ed25519.getPublicKey(seed)).toString("hex");

  const out = opts.out ?? "immuva-key";
  fs.writeFileSync(`${out}.key`, privHex, { mode: 0o600 });
  fs.writeFileSync(`${out}.pub`, pubHex);

  return {
    private_key_hex: privHex,
    public_key_hex: pubHex
  };
}
