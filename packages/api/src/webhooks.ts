import { randomUUID } from "node:crypto";

export type WebhookEvent = "proof.created" | "proof.verified";

export interface WebhookRegistration {
  id: string;
  url: string;
  events: WebhookEvent[];
  created_at: string;
}

export interface WebhookPayload {
  event: WebhookEvent;
  timestamp: string;
  data: unknown;
}

export class WebhookRegistry {
  private readonly store = new Map<string, WebhookRegistration>();

  register(url: string, events: WebhookEvent[]): WebhookRegistration {
    const reg: WebhookRegistration = {
      id: randomUUID(),
      url,
      events,
      created_at: new Date().toISOString(),
    };
    this.store.set(reg.id, reg);
    return reg;
  }

  list(): WebhookRegistration[] {
    return [...this.store.values()];
  }

  async notify(event: WebhookEvent, data: unknown): Promise<void> {
    const payload: WebhookPayload = {
      event,
      timestamp: new Date().toISOString(),
      data,
    };

    const targets = [...this.store.values()].filter((r) =>
      r.events.includes(event)
    );

    await Promise.allSettled(
      targets.map((reg) =>
        fetch(reg.url, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
          signal: AbortSignal.timeout(5000),
        })
      )
    );
  }
}
