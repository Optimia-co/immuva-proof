import { createHash } from "node:crypto";

function sha256(data: string | Buffer): Buffer {
  return createHash("sha256").update(data).digest();
}

/**
 * RFC 6962 leaf hash: 0x00 || sha256(data)
 */
function leafHash(data: string): string {
  const h = createHash("sha256")
    .update(Buffer.from([0x00]))
    .update(Buffer.from(data, "utf8"))
    .digest();
  return h.toString("hex");
}

/**
 * RFC 6962 node hash: sha256(0x01 || left || right)
 */
function nodeHash(left: string, right: string): string {
  const h = createHash("sha256")
    .update(Buffer.from([0x01]))
    .update(Buffer.from(left, "hex"))
    .update(Buffer.from(right, "hex"))
    .digest();
  return h.toString("hex");
}

function buildMerkleRoot(leaves: string[]): string {
  if (leaves.length === 0) return sha256("").toString("hex");
  let level = [...leaves];
  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        next.push(nodeHash(level[i], level[i + 1]));
      } else {
        next.push(level[i]); // RFC 6962 promotion
      }
    }
    level = next;
  }
  return level[0];
}

/**
 * RFC 6962 inclusion proof: returns sibling hashes path from leaf to root.
 */
function inclusionProof(leaves: string[], index: number): string[] {
  if (leaves.length === 0 || index >= leaves.length) return [];
  const path: string[] = [];
  let level = [...leaves];
  let idx   = index;

  while (level.length > 1) {
    const next: string[] = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        const sibling = i === idx ? i + 1 : i + 1 === idx ? i : -1;
        if (sibling !== -1) path.push(level[sibling]);
        next.push(nodeHash(level[i], level[i + 1]));
      } else {
        if (i === idx) { /* no sibling — RFC 6962 promotion */ }
        next.push(level[i]);
      }
    }
    idx   = Math.floor(idx / 2);
    level = next;
  }
  return path;
}

export interface TLogEntry {
  index: number;
  leaf_hash: string;
  data: unknown;
  appended_at: string;
}

export interface TLogProofResponse {
  index: number;
  leaf_hash: string;
  root: string;
  tree_size: number;
  proof: string[];
}

export class TransparencyLog {
  private readonly entries: TLogEntry[] = [];
  private leafHashes: string[]          = [];

  append(data: unknown): TLogEntry {
    const serialized = JSON.stringify(data);
    const lh         = leafHash(serialized);
    const index      = this.entries.length;
    const entry: TLogEntry = {
      index,
      leaf_hash:    lh,
      data,
      appended_at:  new Date().toISOString(),
    };
    this.entries.push(entry);
    this.leafHashes.push(lh);
    return entry;
  }

  latest(): { root: string; tree_size: number } {
    return {
      root:      buildMerkleRoot(this.leafHashes),
      tree_size: this.entries.length,
    };
  }

  proof(index: number): TLogProofResponse | null {
    if (index < 0 || index >= this.entries.length) return null;
    const entry = this.entries[index];
    return {
      index,
      leaf_hash:  entry.leaf_hash,
      root:       buildMerkleRoot(this.leafHashes),
      tree_size:  this.entries.length,
      proof:      inclusionProof(this.leafHashes, index),
    };
  }
}
