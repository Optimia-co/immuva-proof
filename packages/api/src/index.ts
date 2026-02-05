import Fastify from "fastify";
import { loadSDK } from "./sdk-loader.js";

const app = Fastify({ logger: true });

function mustGetEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing env: ${name}`);
  return v;
}

app.post("/v1/proofs", async (req, reply) => {
  const sdk = await loadSDK();
  const body: any = req.body ?? {};

  if (!body.event) return reply.code(400).send({ error: "MISSING:event" });
  if (!body.private_key_hex) return reply.code(400).send({ error: "MISSING:private_key_hex" });
  if (!body.public_key_hex) return reply.code(400).send({ error: "MISSING:public_key_hex" });

  const proof = await sdk.prove(body);
  return { proof };
});

app.post("/v1/verify", async (req, reply) => {
  const sdk = await loadSDK();
  const body: any = req.body ?? {};
  const proof = body.proof;

  if (!proof) return reply.code(400).send({ error: "MISSING:proof" });

  mustGetEnv("IMMUVA_SPEC_ROOT");

  const verdict = await sdk.verify(proof, {
    offline: body.offline ?? true,
    ...(body.ctx ?? {})
  });

  return { verdict };
});

const port = Number(process.env.PORT ?? 8787);
const host = process.env.HOST ?? "127.0.0.1";

app.listen({ port, host }).catch((err) => {
  app.log.error(err);
  process.exit(1);
});
