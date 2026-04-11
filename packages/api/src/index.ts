import Fastify from "fastify";
import { loadSDK } from "./sdk-loader.js";
import { WebhookRegistry } from "./webhooks.js";
import type { WebhookEvent } from "./webhooks.js";
import { TransparencyLog } from "./tlog.js";

const app = Fastify({
  logger: {
    serializers: {
      // Omit request body from logs — it may contain private_key_hex.
      req(req) {
        return { method: req.method, url: req.url };
      },
    },
  },
});

const webhooks = new WebhookRegistry();
const tlog     = new TransparencyLog();

// ── Health endpoint (required by Fly.io) ─────────────────────────────────────
app.get("/health", async () => {
  return { status: "ok", service: "immuva-api", version: "0.2.0" };
});

// ── /v1/proofs ────────────────────────────────────────────────────────────────
app.post("/v1/proofs", async (req, reply) => {
  const sdk = await loadSDK();
  const body: any = req.body ?? {};

  if (!body.event)           return reply.code(400).send({ error: "MISSING:event" });
  if (!body.private_key_hex) return reply.code(400).send({ error: "MISSING:private_key_hex" });
  if (!body.public_key_hex)  return reply.code(400).send({ error: "MISSING:public_key_hex" });

  try {
    const proof = await sdk.prove(body);
    webhooks.notify("proof.created", proof).catch(() => {});
    return { proof };
  } catch (err: any) {
    return reply.code(400).send({
      error: "INVALID_REQUEST",
      message: err?.message ?? "Failed to generate proof",
    });
  }
});

// ── /v1/verify ────────────────────────────────────────────────────────────────
app.post("/v1/verify", async (req, reply) => {
  const sdk = await loadSDK();
  const body: any = req.body ?? {};
  const proof = body.proof;

  if (!proof) return reply.code(400).send({ error: "MISSING:proof" });

  try {
    const verdict = await sdk.verify(proof, {
      offline: body.offline ?? true,
      ...(body.ctx ?? {})
    });
    webhooks.notify("proof.verified", { proof, verdict }).catch(() => {});
    return { verdict };
  } catch (err: any) {
    return reply.code(400).send({
      error: "INVALID_REQUEST",
      message: err?.message ?? "Failed to verify proof",
    });
  }
});

// ── /v1/webhooks/register ─────────────────────────────────────────────────────
app.post("/v1/webhooks/register", async (req, reply) => {
  const body: any = req.body ?? {};

  if (!body.url)    return reply.code(400).send({ error: "MISSING:url" });
  if (!body.events) return reply.code(400).send({ error: "MISSING:events" });
  if (!Array.isArray(body.events) || body.events.length === 0) {
    return reply.code(400).send({ error: "INVALID:events must be a non-empty array" });
  }

  const valid: WebhookEvent[] = ["proof.created", "proof.verified"];
  const invalid = body.events.filter((e: string) => !valid.includes(e as WebhookEvent));
  if (invalid.length > 0) {
    return reply.code(400).send({ error: `INVALID:unknown events: ${invalid.join(", ")}` });
  }

  const registration = webhooks.register(body.url, body.events as WebhookEvent[]);
  return { webhook: registration };
});

// ── /v1/webhooks ──────────────────────────────────────────────────────────────
app.get("/v1/webhooks", async () => {
  return { webhooks: webhooks.list() };
});

// ── /v1/tlog/append ───────────────────────────────────────────────────────────
app.post("/v1/tlog/append", async (req, reply) => {
  const body: any = req.body ?? {};
  if (!body.data) return reply.code(400).send({ error: "MISSING:data" });
  const entry = tlog.append(body.data);
  return { entry, ...tlog.latest() };
});

// ── /v1/tlog/proof/:index ─────────────────────────────────────────────────────
app.get("/v1/tlog/proof/:index", async (req, reply) => {
  const { index } = (req.params as any);
  const result = tlog.proof(Number(index));
  if (!result) return reply.code(404).send({ error: "NOT_FOUND" });
  return result;
});

// ── /v1/tlog/latest ───────────────────────────────────────────────────────────
app.get("/v1/tlog/latest", async () => {
  return tlog.latest();
});

// ── Server startup ────────────────────────────────────────────────────────────
const port = Number(process.env.PORT ?? 3000);
const host = process.env.HOST ?? "0.0.0.0";

app.listen({ port, host }).catch((err) => {
  app.log.error(err);
  process.exit(1);
});
