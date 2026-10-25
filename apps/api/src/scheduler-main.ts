import "reflect-metadata";
import { hostname } from "node:os";
import { NestFactory } from "@nestjs/core";
import { loadEnv, assertProductionConfig } from "@zerosweep/config";
import { createLogger } from "@zerosweep/logger";
import { AppModule } from "./app.module";
import { SecuritySchedulerService } from "./modules/continuous-security/schedules/security-scheduler.service";

const logger = createLogger("zerosweep-scheduler");

/**
 * Standalone scheduler process (Prompt 25 §52): in production topologies the
 * scheduler runs as its OWN deployment, separate from the HTTP API, so API
 * scaling/restarts never disturb schedule evaluation. It drives the same
 * Prompt 22 scheduler service whose database lease guarantees exactly ONE
 * active scheduler control plane at a time — including during failover:
 * standby instances tick harmlessly and the lease decides who acts.
 */
async function bootstrap(): Promise<void> {
  const env = loadEnv();
  assertProductionConfig(env);
  const app = await NestFactory.createApplicationContext(AppModule, { bufferLogs: true });
  const scheduler = app.get(SecuritySchedulerService);
  const owner = env.SCHEDULER_OWNER_ID ?? `scheduler-${hostname()}-${process.pid}`;
  let stopped = false;
  let inFlight = false;

  const runTick = async (): Promise<void> => {
    if (stopped || inFlight) return;
    inFlight = true;
    try {
      const result = await scheduler.tick(new Date(), owner);
      logger.info("scheduler tick", { owner, ...result });
    } catch (err) {
      // A failed tick must not crash-loop the control plane; the lease and
      // the next tick recover. The error is logged with its message only.
      logger.error("scheduler tick failed", { owner, error: err instanceof Error ? err.message : "unknown" });
    } finally {
      inFlight = false;
    }
  };

  const timer = setInterval(() => void runTick(), env.SCHEDULER_TICK_MS);
  await runTick();
  logger.info("scheduler started", { owner, tickMs: env.SCHEDULER_TICK_MS });

  const shutdown = async (signal: string): Promise<void> => {
    if (stopped) return;
    stopped = true;
    clearInterval(timer);
    logger.info("scheduler shutting down", { signal });
    await app.close();
    process.exit(0);
  };
  process.on("SIGTERM", () => void shutdown("SIGTERM"));
  process.on("SIGINT", () => void shutdown("SIGINT"));
}

void bootstrap().catch((err) => {
  logger.error("scheduler failed to start", { error: err instanceof Error ? err.message : "unknown" });
  process.exit(1);
});
