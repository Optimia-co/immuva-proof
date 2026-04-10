# syntax=docker/dockerfile:1
# Build context: monorepo root (fly deploy must be run from repo root)
FROM node:20-alpine AS base
RUN npm install -g pnpm@9

WORKDIR /monorepo

# ── Install dependencies ──────────────────────────────────────────────────────
COPY pnpm-workspace.yaml pnpm-lock.yaml package.json ./
COPY packages/canonical/package.json          packages/canonical/
COPY packages/protocol/package.json           packages/protocol/
COPY packages/receipts/package.json           packages/receipts/
COPY packages/identity/package.json           packages/identity/
COPY packages/non-equivocation/package.json   packages/non-equivocation/
COPY packages/verdict-engine/package.json     packages/verdict-engine/
COPY packages/verifier/package.json           packages/verifier/
COPY packages/fsm/package.json                packages/fsm/
COPY packages/evidence/package.json           packages/evidence/
COPY packages/sdk/package.json                packages/sdk/
COPY packages/api/package.json                packages/api/
COPY packages/cli/package.json                packages/cli/

RUN pnpm install --no-frozen-lockfile --ignore-scripts

# ── Copy sources ──────────────────────────────────────────────────────────────
COPY tsconfig.json ./
COPY tsconfig.base.json ./
COPY packages/canonical/        packages/canonical/
COPY packages/protocol/         packages/protocol/
COPY packages/receipts/         packages/receipts/
COPY packages/identity/         packages/identity/
COPY packages/non-equivocation/ packages/non-equivocation/
COPY packages/verdict-engine/   packages/verdict-engine/
COPY packages/verifier/         packages/verifier/
COPY packages/fsm/              packages/fsm/
COPY packages/evidence/         packages/evidence/
COPY packages/sdk/              packages/sdk/
COPY packages/api/              packages/api/
COPY spec/                      spec/

# ── Build (dependency order) ──────────────────────────────────────────────────
RUN pnpm --filter @immuva/canonical run build
RUN pnpm --filter @immuva/protocol run build
RUN pnpm --filter @immuva/receipts run build
RUN pnpm --filter @immuva/identity run build
RUN pnpm --filter @immuva/non-equivocation run build
RUN pnpm --filter @immuva/verdict-engine run build
RUN pnpm --filter @immuva/verifier run build
RUN pnpm --filter @immuva/fsm run build
RUN pnpm --filter @immuva/evidence run build
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
