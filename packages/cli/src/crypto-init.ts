import * as ed25519 from "@noble/ed25519";
import { createHash } from "node:crypto";
(ed25519 as any).hashes.sha512 = (msg: Uint8Array) =>
  createHash("sha512").update(msg).digest();
export {};
