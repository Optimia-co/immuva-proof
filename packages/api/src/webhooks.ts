import { randomUUID, randomBytes, createHmac } from "node:crypto";

export type WebhookEvent = "proof.created" | "proof.verified";

export interface WebhookRegistration {
  id: string;
  url: string;
  events: WebhookEvent[];
  created_at: string;
  /** HMAC secret — returned once at registration, not stored in list() */
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

export class WebhookRegistry {
  private readonly store = new Map<string, WebhookEntry>();

  register(url: string, events: WebhookEvent[]): WebhookRegistration {
    const secret = randomBytes(32).toString("hex");
    const entry: WebhookEntry = {
      id: randomUUID(),
      url,
      events,
      created_at: new Date().toISOString(),
      secret,
    };
    this.store.set(entry.id, entry);
    // Return secret once — caller must store it
    return { ...entry };
  }

  list(): Omit<WebhookEntry, "secret">[] {
    return [...this.store.values()].map(({ secret: _s, ...rest }) => rest);
  }

  async notify(event: WebhookEvent, data: unknown): Promise<void> {
    const payload: WebhookPayload = {
      event,
      timestamp: new Date().toISOString(),
      data,
    };

    const body = JSON.stringify(payload);
    const targets = [...this.store.values()].filter((r) =>
      r.events.includes(event)
    );

    await Promise.allSettled(
      targets.map((reg) => {
        const sig = createHmac("sha256", reg.secret)
          .update(body)
          .digest("hex");

        return fetch(reg.url, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-Immuva-Signature": `sha256=${sig}`,
          },
          body,
          signal: AbortSignal.timeout(5000),
        });
      })
    );
  }
}
