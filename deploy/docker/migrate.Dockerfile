# syntax=docker/dockerfile:1
# ZeroSweep database migration runner (Prompt 25 §36–§39).
# A dedicated one-shot image: the ONLY production artifact that carries the
# Prisma CLI and the migration files. Application images never run DDL.
# The entrypoint performs preflight checks, then `prisma migrate deploy`
# (which takes Prisma's own migration lock — concurrent runners serialize,
# and deployments invoke exactly one runner per release).
FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS build
WORKDIR /repo
RUN corepack enable && corepack prepare pnpm@9.15.0 --activate
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml ./
COPY packages/database/package.json packages/database/
COPY packages/security-sdk/package.json packages/security-sdk/
COPY packages/ packages/
RUN pnpm install --frozen-lockfile --ignore-scripts --filter @zerosweep/database... \
 && pnpm --filter @zerosweep/database exec prisma generate

FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS runtime
LABEL org.opencontainers.image.title="zerosweep-migrate" \
      org.opencontainers.image.description="ZeroSweep controlled database migration runner (one-shot)" \
      org.opencontainers.image.source="https://github.com/xorudra/zerosweep" \
      org.opencontainers.image.licenses="UNLICENSED"
ENV NODE_ENV=production
WORKDIR /app
COPY --from=build --chown=node:node /repo/node_modules ./node_modules
COPY --from=build --chown=node:node /repo/packages ./packages
COPY --chown=node:node deploy/scripts/migrate.sh ./migrate.sh
USER node
ENTRYPOINT ["sh", "./migrate.sh"]
