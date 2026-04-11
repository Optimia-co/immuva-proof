import Fastify from "fastify";
import rateLimit from "@fastify/rate-limit";
import swagger from "@fastify/swagger";
import swaggerUi from "@fastify/swagger-ui";
import { loadSDK } from "./sdk-loader.js";
import { WebhookRegistry } from "./webhooks.js";
import type { WebhookEvent } from "./webhooks.js";
import { TransparencyLog } from "./tlog.js";
import { AuditLog } from "./audit-log.js";

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

// ── OpenAPI / Swagger ─────────────────────────────────────────────────────────
await app.register(swagger, {
  openapi: {
    openapi: "3.0.3",
    info: {
      title:       "Immuva API",
      version:     "0.3.0",
      description: "Proof-as-a-Service — cryptographic proof generation, verification and transparency log",
    },
    servers: [{ url: "https://immuva-api.fly.dev", description: "Production" }],
    components: {
      securitySchemes: {
        ApiKeyAuth: { type: "apiKey", in: "header", name: "X-Api-Key" },
      },
    },
  },
});

await app.register(swaggerUi, {
  routePrefix: "/docs",
  uiConfig: { docExpansion: "list", deepLinking: true },
});

// ── Rate limiting (per-API-key: 1000/min authenticated, 10/min anonymous) ─────
await app.register(rateLimit, {
  keyGenerator: (req: any) => {
    const key =
      (req.headers["x-api-key"] as string | undefined) ??
      (req.headers["authorization"] as string | undefined)?.replace("Bearer ", "");
    return key ? `key:${key}` : `ip:${req.ip}`;
  },
  max: async (_req: any, key: string) => (key.startsWith("key:") ? 1000 : 10),
  timeWindow: "1 minute",
  errorResponseBuilder: () => ({
    error: "RATE_LIMITED",
    message: "Too many requests, please try again later",
  }),
});

const webhooks = new WebhookRegistry();
const tlog     = new TransparencyLog();
const auditLog = new AuditLog();

// ── API key auth ──────────────────────────────────────────────────────────────
const API_KEY = process.env.IMMUVA_API_KEY ?? "";

function requireApiKey(request: any, reply: any, done: any) {
  if (!API_KEY) return done(); // disabled if not configured
  const key =
    request.headers["x-api-key"] ??
    (request.headers["authorization"] as string | undefined)?.replace("Bearer ", "");
  if (!key || key !== API_KEY) {
    return reply.status(401).send({
      error: "UNAUTHORIZED",
      message: "Missing or invalid API key",
    });
  }
  done();
}

// ── Audit log middleware ──────────────────────────────────────────────────────
app.addHook("onRequest", async (request: any) => {
  request._startTime = Date.now();
});

app.addHook("onSend", async (request: any, reply) => {
  const duration = Date.now() - (request._startTime ?? Date.now());
  const key = request.headers["x-api-key"] as string | undefined;
  auditLog.log({
    endpoint:        request.url,
    method:          request.method,
    api_key_prefix:  key ? key.slice(0, 8) : undefined,
    ip:              request.ip,
    status_code:     reply.statusCode,
    duration_ms:     duration,
  });
});

// ── Health endpoint (required by Fly.io) ─────────────────────────────────────
app.get(
  "/health",
  {
    schema: {
      summary: "Health check",
      tags: ["System"],
      response: {
        200: {
          type: "object",
          properties: {
            status:  { type: "string" },
            service: { type: "string" },
            version: { type: "string" },
          },
        },
      },
    },
  },
  async () => ({ status: "ok", service: "immuva-api", version: "0.3.0" })
);

// ── /v1/proofs ────────────────────────────────────────────────────────────────
app.post(
  "/v1/proofs",
  {
    preHandler: requireApiKey,
    schema: {
      summary: "Generate a cryptographic proof",
      tags: ["Proofs"],
      security: [{ ApiKeyAuth: [] }],
      body: {
        type: "object",
        required: ["event", "public_key_hex", "private_key_hex"],
        properties: {
          event:           { type: "object", description: "The event to prove" },
          public_key_hex:  { type: "string", minLength: 64, maxLength: 64, description: "Ed25519 public key (hex)" },
          private_key_hex: { type: "string", minLength: 128, maxLength: 128, description: "Ed25519 private key (hex)" },
          agent_id:        { type: "string", description: "Agent identifier" },
          resultset_present: { type: "boolean" },
          evidence:        { type: "object" },
          outcome:         { type: "object" },
        },
      },
      response: {
        200: {
          type: "object",
          properties: { proof: { type: "object" } },
        },
        400: {
          type: "object",
          properties: { error: { type: "string" }, message: { type: "string" } },
        },
        401: {
          type: "object",
          properties: { error: { type: "string" }, message: { type: "string" } },
        },
      },
    },
  },
  async (req, reply) => {
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
        error:   "INVALID_REQUEST",
        message: err?.message ?? "Failed to generate proof",
      });
    }
  }
);

// ── /v1/verify ────────────────────────────────────────────────────────────────
app.post(
  "/v1/verify",
  {
    schema: {
      summary: "Verify a proof offline",
      tags: ["Proofs"],
      body: {
        type: "object",
        required: ["proof"],
        properties: {
          proof:   { type: "object", description: "The ProofBundle to verify" },
          offline: { type: "boolean", default: true },
          ctx:     { type: "object" },
        },
      },
      response: {
        200: {
          type: "object",
          properties: { verdict: { type: "object" } },
        },
        400: {
          type: "object",
          properties: { error: { type: "string" }, message: { type: "string" } },
        },
      },
    },
  },
  async (req, reply) => {
    const sdk = await loadSDK();
    const body: any = req.body ?? {};
    const proof = body.proof;

    if (!proof) return reply.code(400).send({ error: "MISSING:proof" });

    try {
      const verdict = await sdk.verify(proof, {
        offline: body.offline ?? true,
        ...(body.ctx ?? {}),
      });
      webhooks.notify("proof.verified", { proof, verdict }).catch(() => {});
      return { verdict };
    } catch (err: any) {
      return reply.code(400).send({
        error:   "INVALID_REQUEST",
        message: err?.message ?? "Failed to verify proof",
      });
    }
  }
);

// ── /v1/webhooks/register ─────────────────────────────────────────────────────
app.post(
  "/v1/webhooks/register",
  {
    preHandler: requireApiKey,
    schema: {
      summary: "Register a webhook endpoint",
      tags: ["Webhooks"],
      security: [{ ApiKeyAuth: [] }],
      body: {
        type: "object",
        required: ["url", "events"],
        properties: {
          url:    { type: "string", format: "uri" },
          events: {
            type:  "array",
            items: { type: "string", enum: ["proof.created", "proof.verified"] },
            minItems: 1,
          },
        },
      },
      response: {
        200: {
          type: "object",
          properties: {
            webhook: {
              type: "object",
              properties: {
                id:         { type: "string" },
                url:        { type: "string" },
                events:     { type: "array", items: { type: "string" } },
                created_at: { type: "string" },
                secret:     { type: "string", description: "HMAC secret — shown once" },
              },
            },
          },
        },
      },
    },
  },
  async (req, reply) => {
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

    const registration = await webhooks.register(body.url, body.events as WebhookEvent[]);
    return { webhook: registration };
  }
);

// ── /v1/webhooks ──────────────────────────────────────────────────────────────
app.get(
  "/v1/webhooks",
  {
    schema: {
      summary: "List registered webhooks",
      tags: ["Webhooks"],
      response: {
        200: {
          type: "object",
          properties: {
            webhooks: {
              type:  "array",
              items: {
                type: "object",
                properties: {
                  id:         { type: "string" },
                  url:        { type: "string" },
                  events:     { type: "array", items: { type: "string" } },
                  created_at: { type: "string" },
                },
              },
            },
          },
        },
      },
    },
  },
  async () => ({ webhooks: await webhooks.list() })
);

// ── DELETE /v1/webhooks/:id ───────────────────────────────────────────────────
app.delete(
  "/v1/webhooks/:id",
  {
    preHandler: requireApiKey,
    schema: {
      summary: "Delete a webhook",
      tags: ["Webhooks"],
      security: [{ ApiKeyAuth: [] }],
      params: {
        type: "object",
        properties: { id: { type: "string" } },
      },
      response: {
        200: {
          type: "object",
          properties: { deleted: { type: "string" } },
        },
        404: {
          type: "object",
          properties: { error: { type: "string" } },
        },
      },
    },
  },
  async (req, reply) => {
    const { id } = req.params as any;
    const ok = await webhooks.delete(id);
    if (!ok) return reply.code(404).send({ error: "NOT_FOUND" });
    return { deleted: id };
  }
);

// ── /v1/tlog/append ───────────────────────────────────────────────────────────
app.post(
  "/v1/tlog/append",
  {
    preHandler: requireApiKey,
    schema: {
      summary: "Append an entry to the transparency log",
      tags: ["TLog"],
      security: [{ ApiKeyAuth: [] }],
      body: {
        type: "object",
        required: ["data"],
        properties: { data: { type: "object" } },
      },
    },
  },
  async (req, reply) => {
    const body: any = req.body ?? {};
    if (!body.data) return reply.code(400).send({ error: "MISSING:data" });
    const entry  = await tlog.append(body.data);
    const latest = await tlog.latest();
    return { entry, ...latest };
  }
);

// ── /v1/tlog/proof/:index ─────────────────────────────────────────────────────
app.get(
  "/v1/tlog/proof/:index",
  {
    schema: {
      summary: "Get Merkle inclusion proof for a TLog entry",
      tags: ["TLog"],
      params: {
        type: "object",
        properties: { index: { type: "string" } },
      },
    },
  },
  async (req, reply) => {
    const { index } = req.params as any;
    const result = await tlog.proof(Number(index));
    if (!result) return reply.code(404).send({ error: "NOT_FOUND" });
    return result;
  }
);

// ── /v1/tlog/latest ───────────────────────────────────────────────────────────
app.get(
  "/v1/tlog/latest",
  {
    schema: {
      summary: "Get current Merkle root and tree size",
      tags: ["TLog"],
      response: {
        200: {
          type: "object",
          properties: {
            root:      { type: "string" },
            tree_size: { type: "number" },
          },
        },
      },
    },
  },
  async () => tlog.latest()
);

// ── /v1/audit ─────────────────────────────────────────────────────────────────
app.get(
  "/v1/audit",
  {
    preHandler: requireApiKey,
    schema: {
      summary: "Get recent API audit log entries",
      tags: ["System"],
      security: [{ ApiKeyAuth: [] }],
      querystring: {
        type: "object",
        properties: {
          limit: { type: "number", default: 100, maximum: 500 },
        },
      },
      response: {
        200: {
          type: "object",
          properties: {
            entries: {
              type:  "array",
              items: {
                type: "object",
                properties: {
                  endpoint:        { type: "string" },
                  method:          { type: "string" },
                  api_key_prefix:  { type: "string" },
                  ip:              { type: "string" },
                  status_code:     { type: "number" },
                  duration_ms:     { type: "number" },
                  created_at:      { type: "string" },
                },
              },
            },
          },
        },
      },
    },
  },
  async (req) => {
    const { limit = 100 } = (req.query as any);
    return { entries: await auditLog.recent(Math.min(limit, 500)) };
  }
);

// ── Server startup ────────────────────────────────────────────────────────────
const port = Number(process.env.PORT ?? 3000);
const host = process.env.HOST ?? "0.0.0.0";

app.listen({ port, host }).catch((err) => {
  app.log.error(err);
  process.exit(1);
});
