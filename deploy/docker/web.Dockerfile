# syntax=docker/dockerfile:1
# ZeroSweep web console — production image (Prompt 25 §6–§19).
FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS deps
WORKDIR /repo
RUN corepack enable && corepack prepare pnpm@9.15.0 --activate
COPY pnpm-workspace.yaml package.json pnpm-lock.yaml ./
COPY apps/web/package.json apps/web/
COPY packages/ packages/
RUN pnpm fetch --frozen-lockfile || pnpm install --frozen-lockfile --ignore-scripts

FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS build
WORKDIR /repo
RUN corepack enable && corepack prepare pnpm@9.15.0 --activate
COPY . .
COPY --from=deps /repo/node_modules ./node_modules
ARG NEXT_PUBLIC_API_BASE_URL=/api/v1
ENV NEXT_PUBLIC_API_BASE_URL=${NEXT_PUBLIC_API_BASE_URL} NEXT_TELEMETRY_DISABLED=1
RUN pnpm install --frozen-lockfile --ignore-scripts \
 && pnpm --filter @dsrclone/web... build \
 && pnpm --filter @dsrclone/web deploy --prod /out

FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS runtime
LABEL org.opencontainers.image.title="dsrclone-web" \
      org.opencontainers.image.description="ZeroSweep web console" \
      org.opencontainers.image.source="https://github.com/xorudra/zerosweep" \
      org.opencontainers.image.licenses="UNLICENSED"
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1
WORKDIR /app
COPY --from=build --chown=node:node /out ./
COPY --from=build --chown=node:node /repo/apps/web/.next ./.next
USER node
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3000/').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["./node_modules/.bin/next", "start", "-p", "3000"]
