# syntax=docker/dockerfile:1
# ZeroSweep scheduler — production image (Prompt 25 §12/§52).
# Same build as the API (the scheduler entrypoint ships in the API package),
# different command: the standalone Prompt 22 scheduler loop, lease-guarded
# so exactly one scheduler control plane is active platform-wide.
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
LABEL org.opencontainers.image.title="zerosweep-scheduler" \
      org.opencontainers.image.description="ZeroSweep standalone scheduler (Prompt 22 lease)" \
      org.opencontainers.image.source="https://github.com/xorudra/zerosweep" \
      org.opencontainers.image.licenses="UNLICENSED"
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build --chown=node:node /out ./
USER node
CMD ["node", "dist/scheduler-main.js"]
