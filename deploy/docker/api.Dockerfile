# syntax=docker/dockerfile:1
# ZeroSweep API — production image (Prompt 25 §6–§19).
# Multi-stage: deps -> build -> pruned runtime via pnpm deploy.
# Non-root runtime, digest-pinned base, OCI labels, immutable inputs.
FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS deps
WORKDIR /repo
RUN corepack enable && corepack prepare pnpm@9.15.0 --activate
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml ./
COPY apps/api/package.json apps/api/
COPY packages/ packages/
RUN pnpm fetch --frozen-lockfile || pnpm install --frozen-lockfile --ignore-scripts

FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS build
WORKDIR /repo
RUN corepack enable && corepack prepare pnpm@9.15.0 --activate
COPY . .
COPY --from=deps /repo/node_modules ./node_modules
RUN pnpm install --frozen-lockfile --ignore-scripts \
 && pnpm --filter @zerosweep/api... build \
 && pnpm --filter @zerosweep/api deploy --prod /out \
 && cp -r apps/api/dist /out/dist

FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS runtime
LABEL org.opencontainers.image.title="zerosweep-api" \
      org.opencontainers.image.description="ZeroSweep API service" \
      org.opencontainers.image.source="https://github.com/xorudra/zerosweep" \
      org.opencontainers.image.licenses="UNLICENSED"
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build --chown=node:node /out ./
USER node
EXPOSE 4000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:4000/api/v1/health/live').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "dist/main.js"]
