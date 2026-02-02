import { createHash } from "node:crypto";

export const sha256 = (b: Buffer): Buffer =>
  createHash("sha256").update(b).digest();

export function merkleRoot(leaves: Buffer[]): Buffer {
  if (leaves.length === 0) {
    return sha256(Buffer.alloc(0));
  }

  let level: Buffer[] = leaves.map(l => sha256(l));

  while (level.length > 1) {
    const next: Buffer[] = [];

    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        next.push(
          sha256(Buffer.concat([level[i], level[i + 1]]))
        );
      } else {
        // RFC6962 promotion
        next.push(level[i]);
      }
    }

    level = next;
  }

  return level[0];
}
