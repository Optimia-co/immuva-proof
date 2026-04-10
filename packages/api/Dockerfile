# syntax=docker/dockerfile:1
# Build context: monorepo root (fly deploy must be run from repo root)
FROM node:20-alpine AS base
RUN npm install -g pnpm@9

WORKDIR /monorepo

# ── Install dependencies ──────────────────────────────────────────────────────
COPY pnpm-workspace.yaml pnpm-lock.yaml package.json ./
COPY packages/canonical/package.json          packages/canonical/
COPY packages/protocol/package.json           packages/protocol/
COPY packages/verifier/package.json           packages/verifier/
COPY packages/fsm/package.json                packages/fsm/
COPY packages/evidence/package.json           packages/evidence/
COPY packages/sdk/package.json                packages/sdk/
COPY packages/api/package.json                packages/api/

# Stub out other workspace packages so pnpm install resolves the graph
COPY packages/cli/package.json                packages/cli/

RUN pnpm install --no-frozen-lockfile --ignore-scripts

# ── Copy sources ──────────────────────────────────────────────────────────────
COPY tsconfig.json ./
COPY tsconfig.base.json ./
COPY packages/canonical/   packages/canonical/
COPY packages/protocol/    packages/protocol/
COPY packages/verifier/    packages/verifier/
COPY packages/fsm/         packages/fsm/
COPY packages/evidence/    packages/evidence/
COPY packages/sdk/         packages/sdk/
COPY packages/api/         packages/api/
COPY spec/                 spec/

# ── Build ─────────────────────────────────────────────────────────────────────
# Root tsc -b builds canonical, protocol, verifier, fsm, evidence (composite refs)
RUN pnpm build || true
# SDK and API are not in root tsconfig references — build them explicitly
RUN pnpm --filter @immuva/sdk run build
RUN pnpm --filter @immuva/api run build

# ── Runtime image ─────────────────────────────────────────────────────────────
FROM node:20-alpine AS runtime
RUN npm install -g pnpm@9

WORKDIR /monorepo

# Copy the full built monorepo (node_modules + dist files)
COPY --from=base /monorepo ./

EXPOSE 3000

CMD ["node", "packages/api/dist/index.js"]
