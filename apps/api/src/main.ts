import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import type { NestExpressApplication } from "@nestjs/platform-express";
import type { NextFunction, Request, Response } from "express";
import helmet from "helmet";
import { loadEnv, assertProductionConfig, API_PREFIX } from "@dsrclone/config";
import { createLogger } from "@dsrclone/logger";
import { AppModule } from "./app.module";
import { HttpExceptionFilter } from "./common/filters/http-exception.filter";
import { MetricsService } from "./health/metrics.service";
import { rateLimitMiddleware, requestIdMiddleware } from "./common/middleware/request-id.middleware";

const logger = createLogger("dsrclone-api");

async function bootstrap(): Promise<void> {
  const env = loadEnv();
  // Prompt 25 §30/§33: fail fast on placeholder secrets / unsafe production config.
  assertProductionConfig(env);
  const app = await NestFactory.create<NestExpressApplication>(AppModule, { bufferLogs: true });
  app.setGlobalPrefix(API_PREFIX);
  app.use(helmet());
  app.enableCors({ origin: env.API_CORS_ORIGIN.split(",").map((s) => s.trim()), credentials: true });
  app.use(requestIdMiddleware);
  app.use(rateLimitMiddleware(300, 60_000));
  // Prompt 25 §102: Prometheus request counters (bounded labels only).
  app.use(app.get(MetricsService).middleware());
  // Prompt 24 §15/§82: inbound provider webhooks are authenticated by
  // HMAC over the EXACT bytes received, so the raw body is captured
  // for webhook paths before the JSON parser consumes the stream.
  // Collection is hard-capped; oversize deliveries are rejected by
  // the webhook service's own size check with an audit record.
  app.use((req: Request, _res: Response, next: NextFunction) => {
    const url = req.url ?? "";
    if (!url.startsWith(`/${API_PREFIX}/webhooks/`)) return next();
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size <= 2_000_000) chunks.push(chunk);
    });
    req.on("end", () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      (req as { rawBody?: string }).rawBody = raw;
      try {
        (req as { body?: unknown }).body = JSON.parse(raw);
      } catch {
        (req as { body?: unknown }).body = {};
      }
      (req as { _body?: boolean })._body = true;
      next();
    });
    req.on("error", () => next());
  });
  app.useBodyParser("json", { limit: "1mb" });
  app.useBodyParser("urlencoded", { limit: "1mb", extended: true });
  app.useGlobalFilters(new HttpExceptionFilter());
  app.enableShutdownHooks();
  await app.listen(env.API_PORT);
  logger.info("api listening", { port: env.API_PORT, prefix: API_PREFIX });
}

void bootstrap().catch((err) => {
  logger.error("api failed to start", { error: err instanceof Error ? err.message : "unknown" });
  process.exit(1);
});
