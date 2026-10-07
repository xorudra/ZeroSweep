import "reflect-metadata";
import { NestFactory } from "@nestjs/core";
import type { NestExpressApplication } from "@nestjs/platform-express";
import helmet from "helmet";
import { loadEnv, API_PREFIX } from "@dsrclone/config";
import { createLogger } from "@dsrclone/logger";
import { AppModule } from "./app.module";
import { HttpExceptionFilter } from "./common/filters/http-exception.filter";
import { rateLimitMiddleware, requestIdMiddleware } from "./common/middleware/request-id.middleware";

const logger = createLogger("dsrclone-api");

async function bootstrap(): Promise<void> {
  const env = loadEnv();
  const app = await NestFactory.create<NestExpressApplication>(AppModule, { bufferLogs: true });
  app.setGlobalPrefix(API_PREFIX);
  app.use(helmet());
  app.enableCors({ origin: env.API_CORS_ORIGIN.split(",").map((s) => s.trim()), credentials: true });
  app.use(requestIdMiddleware);
  app.use(rateLimitMiddleware(300, 60_000));
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
