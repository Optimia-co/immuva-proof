import { createHash } from "node:crypto";
import { createClient, SupabaseClient } from "@supabase/supabase-js";

// ── Merkle helpers (RFC 6962) ─────────────────────────────────────────────
function sha256(data: string | Buffer): Buffer {
  return createHash("sha256").update(data).digest();
}

function leafHash(data: string): string {
  return createHash("sha256")
    .update(Buffer.from([0x00]))
    .update(Buffer.from(data, "utf8"))
    .digest("hex");
}

function nodeHash(left: string, right: string): string {
  return createHash("sha256")
    .update(Buffer.from([0x01]))
    .update(Buffer.from(left, "hex"))
    .update(Buffer.from(right, "hex"))
    .digest("hex");
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

// ── Supabase client (optional) ─────────────────────────────────────────────
// SQL to create the table (run once in Supabase SQL Editor):
//
// CREATE TABLE IF NOT EXISTS public.tlog_entries (
//   id serial PRIMARY KEY,
//   proof_id text NOT NULL,
//   canonical_hash text NOT NULL,
//   merkle_root text NOT NULL,
//   created_at timestamptz DEFAULT now()
// );
// ALTER TABLE public.tlog_entries ENABLE ROW LEVEL SECURITY;
// CREATE POLICY "service_all" ON public.tlog_entries USING (true) WITH CHECK (true);

function makeSupabase(): SupabaseClient | null {
  const url = process.env.SUPABASE_URL ?? "";
  const key = process.env.SUPABASE_SERVICE_KEY ?? "";
  if (!url || !key) return null;
  return createClient(url, key, { auth: { persistSession: false } });
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
  private readonly memEntries: TLogEntry[] = [];
  private memLeaves: string[] = [];
  private readonly db: SupabaseClient | null;

  constructor() {
    this.db = makeSupabase();
  }

  async append(data: unknown): Promise<TLogEntry> {
    const serialized = JSON.stringify(data);
    const lh = leafHash(serialized);

    if (this.db) {
      // Compute root after adding this leaf
      const { count } = await this.db
        .from("tlog_entries")
        .select("*", { count: "exact", head: true })
        .throwOnError();

      const index = count ?? 0;

      // Fetch all existing leaf hashes to compute new root
      const { data: rows, error } = await this.db
        .from("tlog_entries")
        .select("canonical_hash")
        .order("id", { ascending: true });

      const leaves = (rows ?? []).map((r: any) => r.canonical_hash);
      leaves.push(lh);
      const root = buildMerkleRoot(leaves);

      const { error: insertErr } = await this.db.from("tlog_entries").insert({
        proof_id:       serialized.slice(0, 64),
        canonical_hash: lh,
        merkle_root:    root,
      });

      if (insertErr || error) {
        console.error("[tlog] DB error:", insertErr?.message ?? error?.message);
        // Fallback to memory
        return this._appendMemory(data, lh);
      }

      const entry: TLogEntry = {
        index,
        leaf_hash:   lh,
        data,
        appended_at: new Date().toISOString(),
      };
      return entry;
    }

    return this._appendMemory(data, lh);
  }

  private _appendMemory(data: unknown, lh: string): TLogEntry {
    const index = this.memEntries.length;
    const entry: TLogEntry = { index, leaf_hash: lh, data, appended_at: new Date().toISOString() };
    this.memEntries.push(entry);
    this.memLeaves.push(lh);
    return entry;
  }

  async latest(): Promise<{ root: string; tree_size: number }> {
    if (this.db) {
      const { data: last, count, error } = await this.db
        .from("tlog_entries")
        .select("merkle_root", { count: "exact" })
        .order("id", { ascending: false })
        .limit(1);

      if (!error) {
        return {
          root:      last?.[0]?.merkle_root ?? sha256("").toString("hex"),
          tree_size: count ?? 0,
        };
      }
      console.error("[tlog] DB latest error:", error.message);
    }

    return {
      root:      buildMerkleRoot(this.memLeaves),
      tree_size: this.memEntries.length,
    };
  }

  async proof(index: number): Promise<TLogProofResponse | null> {
    if (this.db) {
      const { data: rows, error } = await this.db
        .from("tlog_entries")
        .select("canonical_hash")
        .order("id", { ascending: true });

      if (!error && rows) {
        const leaves = rows.map((r: any) => r.canonical_hash);
        if (index < 0 || index >= leaves.length) return null;
        return {
          index,
          leaf_hash:  leaves[index],
          root:       buildMerkleRoot(leaves),
          tree_size:  leaves.length,
          proof:      inclusionProof(leaves, index),
        };
      }
      console.error("[tlog] DB proof error:", error?.message);
    }

    if (index < 0 || index >= this.memEntries.length) return null;
    const entry = this.memEntries[index];
    return {
      index,
      leaf_hash:  entry.leaf_hash,
      root:       buildMerkleRoot(this.memLeaves),
      tree_size:  this.memEntries.length,
      proof:      inclusionProof(this.memLeaves, index),
    };
  }
}
