FROM node:20-alpine AS base
RUN corepack enable && corepack prepare pnpm@9.15.0 --activate
WORKDIR /app
COPY . .
RUN pnpm install --frozen-lockfile && pnpm --filter @zerosweep/api build
EXPOSE 4000
CMD ["node", "apps/api/dist/main.js"]
