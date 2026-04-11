import { randomUUID, randomBytes, createHmac } from "node:crypto";
import { createClient, SupabaseClient } from "@supabase/supabase-js";

export type WebhookEvent = "proof.created" | "proof.verified";

export interface WebhookRegistration {
  id: string;
  url: string;
  events: WebhookEvent[];
  created_at: string;
  /** HMAC secret — returned once at registration */
  secret?: string;
}

interface WebhookEntry {
  id: string;
  url: string;
  events: WebhookEvent[];
  created_at: string;
  secret: string;
}

export interface WebhookPayload {
  event: WebhookEvent;
  timestamp: string;
  data: unknown;
}

// ── Supabase client (optional) ─────────────────────────────────────────────
// SQL to create the table (run once in Supabase SQL Editor):
//
// CREATE TABLE IF NOT EXISTS public.webhooks (
//   id uuid DEFAULT gen_random_uuid() PRIMARY KEY,
//   url text NOT NULL,
//   events text[] NOT NULL,
//   secret text NOT NULL,
//   created_at timestamptz DEFAULT now()
// );
// ALTER TABLE public.webhooks ENABLE ROW LEVEL SECURITY;
// CREATE POLICY "service_all" ON public.webhooks USING (true) WITH CHECK (true);

function makeSupabase(): SupabaseClient | null {
  const url = process.env.SUPABASE_URL ?? "";
  const key = process.env.SUPABASE_SERVICE_KEY ?? "";
  if (!url || !key) return null;
  return createClient(url, key, { auth: { persistSession: false } });
}

export class WebhookRegistry {
  private readonly mem = new Map<string, WebhookEntry>();
  private readonly db: SupabaseClient | null;

  constructor() {
    this.db = makeSupabase();
  }

  async register(url: string, events: WebhookEvent[]): Promise<WebhookRegistration> {
    const secret = randomBytes(32).toString("hex");
    const id = randomUUID();
    const created_at = new Date().toISOString();
    const entry: WebhookEntry = { id, url, events, created_at, secret };

    if (this.db) {
      const { error } = await this.db
        .from("webhooks")
        .insert({ id, url, events, secret, created_at });
      if (error) {
        // Fallback to memory on DB error
        console.error("[webhooks] DB insert failed:", error.message);
        this.mem.set(id, entry);
      }
    } else {
      this.mem.set(id, entry);
    }

    return { ...entry };
  }

  async list(): Promise<Omit<WebhookEntry, "secret">[]> {
    if (this.db) {
      const { data, error } = await this.db
        .from("webhooks")
        .select("id, url, events, created_at")
        .order("created_at", { ascending: false });
      if (!error && data) {
        return data as Omit<WebhookEntry, "secret">[];
      }
      console.error("[webhooks] DB select failed:", error?.message);
    }
    return [...this.mem.values()].map(({ secret: _s, ...rest }) => rest);
  }

  async delete(id: string): Promise<boolean> {
    if (this.db) {
      const { error } = await this.db.from("webhooks").delete().eq("id", id);
      if (error) {
        console.error("[webhooks] DB delete failed:", error.message);
        return false;
      }
      return true;
    }
    return this.mem.delete(id);
  }

  async notify(event: WebhookEvent, data: unknown): Promise<void> {
    const payload: WebhookPayload = {
      event,
      timestamp: new Date().toISOString(),
      data,
    };
    const body = JSON.stringify(payload);

    let targets: WebhookEntry[] = [];

    if (this.db) {
      const { data: rows, error } = await this.db
        .from("webhooks")
        .select("id, url, events, secret, created_at")
        .contains("events", [event]);
      if (!error && rows) {
        targets = rows as WebhookEntry[];
      } else {
        // Fallback to memory on DB error
        targets = [...this.mem.values()].filter((r) => r.events.includes(event));
      }
    } else {
      targets = [...this.mem.values()].filter((r) => r.events.includes(event));
    }

    await Promise.allSettled(
      targets.map((reg) => {
        const sig = createHmac("sha256", reg.secret)
          .update(body)
          .digest("hex");

        return fetchWithRetry(reg.url, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Immuva-Signature": `sha256=${sig}`,
          },
          body,
        });
      })
    );
  }
}

// ── Retry helper with exponential backoff ─────────────────────────────────────
async function fetchWithRetry(
  url: string,
  init: RequestInit,
  attempts = 3,
  delaysMs: number[] = [1000, 5000, 30000]
): Promise<void> {
  for (let i = 0; i < attempts; i++) {
    try {
      const res = await fetch(url, {
        ...init,
        signal: AbortSignal.timeout(10_000),
      });
      if (res.ok) return;
      console.warn(`[webhook] attempt ${i + 1}/${attempts} → HTTP ${res.status} for ${url}`);
    } catch (err: any) {
      console.warn(`[webhook] attempt ${i + 1}/${attempts} failed for ${url}: ${err.message}`);
    }
    if (i < attempts - 1) {
      await new Promise((r) => setTimeout(r, delaysMs[i]));
    }
  }
  console.error(`[webhook] all ${attempts} attempts failed for ${url}`);
}
