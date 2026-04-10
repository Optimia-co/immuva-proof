import Fastify from "fastify";
import { loadSDK } from "./sdk-loader.js";

const app = Fastify({ logger: true });

// ── Health endpoint (required by Fly.io) ─────────────────────────────────────
app.get("/health", async () => {
  return { status: "ok", service: "immuva-api", version: "0.1.0" };
});

// ── /v1/proofs ────────────────────────────────────────────────────────────────
app.post("/v1/proofs", async (req, reply) => {
  const sdk = await loadSDK();
  const body: any = req.body ?? {};

  if (!body.event)           return reply.code(400).send({ error: "MISSING:event" });
  if (!body.private_key_hex) return reply.code(400).send({ error: "MISSING:private_key_hex" });
  if (!body.public_key_hex)  return reply.code(400).send({ error: "MISSING:public_key_hex" });

  const proof = await sdk.prove(body);
  return { proof };
});

// ── /v1/verify ────────────────────────────────────────────────────────────────
app.post("/v1/verify", async (req, reply) => {
  const sdk = await loadSDK();
  const body: any = req.body ?? {};
  const proof = body.proof;

  if (!proof) return reply.code(400).send({ error: "MISSING:proof" });

  // IMMUVA_SPEC_ROOT is required for registry-backed severity lookup.
  // If absent, the verifier falls back to offline mode with a degraded response.
  const specRoot = process.env.IMMUVA_SPEC_ROOT;
  if (!specRoot) {
    app.log.warn("IMMUVA_SPEC_ROOT not set — verifier will return REGISTRY_UNAVAILABLE");
  }

  const verdict = await sdk.verify(proof, {
    offline: body.offline ?? true,
    ...(body.ctx ?? {})
  });

  return { verdict };
});

// ── Server startup ────────────────────────────────────────────────────────────
const port = Number(process.env.PORT ?? 3000);
const host = process.env.HOST ?? "0.0.0.0";

app.listen({ port, host }).catch((err) => {
  app.log.error(err);
  process.exit(1);
});
