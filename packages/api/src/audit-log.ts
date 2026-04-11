import { createClient, SupabaseClient } from "@supabase/supabase-js";

// ── Supabase client (optional) ─────────────────────────────────────────────
// SQL to create the table (run once in Supabase SQL Editor):
//
// CREATE TABLE IF NOT EXISTS public.api_audit_log (
//   id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
//   endpoint text NOT NULL,
//   method text NOT NULL,
//   api_key_prefix text,
//   ip text,
//   status_code int,
//   duration_ms int,
//   created_at timestamptz DEFAULT now()
// );
// ALTER TABLE public.api_audit_log ENABLE ROW LEVEL SECURITY;
// CREATE POLICY service_all ON public.api_audit_log USING (true) WITH CHECK (true);

function makeSupabase(): SupabaseClient | null {
  const url = process.env.SUPABASE_URL ?? "";
  const key = process.env.SUPABASE_SERVICE_KEY ?? "";
  if (!url || !key) return null;
  return createClient(url, key, { auth: { persistSession: false } });
}

export interface AuditEntry {
  endpoint: string;
  method: string;
  api_key_prefix?: string;
  ip?: string;
  status_code: number;
  duration_ms: number;
}

export class AuditLog {
  private readonly db: SupabaseClient | null = makeSupabase();

  async log(entry: AuditEntry): Promise<void> {
    if (!this.db) return;
    // Non-blocking — errors are swallowed to never affect response path
    this.db.from("api_audit_log").insert(entry).then(({ error }) => {
      if (error) console.warn("[audit] insert failed:", error.message);
    });
  }

  async recent(limit = 100): Promise<AuditEntry[]> {
    if (!this.db) return [];
    const { data, error } = await this.db
      .from("api_audit_log")
      .select("*")
      .order("created_at", { ascending: false })
      .limit(limit);
    if (error) {
      console.warn("[audit] select failed:", error.message);
      return [];
    }
    return (data ?? []) as AuditEntry[];
  }
}
