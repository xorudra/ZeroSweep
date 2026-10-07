FROM node:20-alpine AS base
RUN corepack enable && corepack prepare pnpm@9.15.0 --activate
WORKDIR /app
COPY . .
RUN pnpm install --frozen-lockfile && pnpm --filter @dsrclone/web build
EXPOSE 3000
CMD ["node_modules/.bin/next", "start", "apps/web"]
