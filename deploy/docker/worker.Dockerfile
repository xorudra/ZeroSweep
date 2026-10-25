# syntax=docker/dockerfile:1
# ZeroSweep worker — production image (Prompt 25 §6–§19, §53–§60).
# One image per worker POOL via the DSRCLONE_WORKER_TYPE build arg; scanner
# tool layers belong in derived per-pool images so a pool only carries the
# tools its ScannerCapabilityPolicy allows. The worker NEVER runs privileged
# and NEVER receives a Docker socket or host mounts.
FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS deps
WORKDIR /repo
RUN corepack enable && corepack prepare pnpm@9.15.0 --activate
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml ./
COPY apps/worker/package.json apps/worker/
COPY packages/ packages/
RUN pnpm fetch --frozen-lockfile || pnpm install --frozen-lockfile --ignore-scripts

FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS build
WORKDIR /repo
RUN corepack enable && corepack prepare pnpm@9.15.0 --activate
COPY . .
COPY --from=deps /repo/node_modules ./node_modules
RUN pnpm install --frozen-lockfile --ignore-scripts \
 && pnpm --filter @dsrclone/worker... build \
 && pnpm --filter @dsrclone/worker deploy --prod /out \
 && cp -r apps/worker/dist /out/dist

FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS runtime
LABEL org.opencontainers.image.title="dsrclone-worker" \
      org.opencontainers.image.description="ZeroSweep scan worker (pool selected by DSRCLONE_WORKER_TYPE)" \
      org.opencontainers.image.source="https://github.com/xorudra/dsrclone" \
      org.opencontainers.image.licenses="UNLICENSED"
ARG DSRCLONE_WORKER_TYPE=GENERAL_WEB
ENV NODE_ENV=production \
    DSRCLONE_WORKER_TYPE=${DSRCLONE_WORKER_TYPE} \
    WORKER_HEARTBEAT_FILE=/tmp/dsrclone-worker-heartbeat.json
WORKDIR /app
COPY --from=build --chown=node:node /out ./
USER node
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "const fs=require('fs');try{const h=JSON.parse(fs.readFileSync(process.env.WORKER_HEARTBEAT_FILE,'utf8'));process.exit(Date.now()-new Date(h.at).getTime()<90000?0:1)}catch{process.exit(1)}"
CMD ["node", "dist/index.js"]
