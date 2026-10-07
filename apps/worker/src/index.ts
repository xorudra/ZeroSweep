import { Worker, type Job } from "bullmq";
import { QUEUES } from "@dsrclone/config";
import { createLogger } from "@dsrclone/logger";
import { createRedisConnection } from "./connection";
import { reportHealth, type WorkerHealth } from "./health";
import type { OrchestrationJobData, PlaceholderJobData } from "./jobs";

const logger = createLogger("dsrclone-worker");
const connection = createRedisConnection();

let redisConnected = false;
connection.on("ready", () => { redisConnected = true; logger.info("redis connected"); });
connection.on("error", (err) => { redisConnected = false; logger.error("redis connection error", { error: err.message }); });

async function handlePlaceholder(job: Job<PlaceholderJobData>): Promise<{ ok: true; jobId: string }> {
  const log = logger.child({ scanId: undefined, requestId: job.id });
  log.info("placeholder job received", { jobId: job.id, kind: job.data.kind });
  await new Promise((resolve) => setTimeout(resolve, 250)); // brief, harmless wait
  log.info("placeholder job completed", { jobId: job.id });
  return { ok: true, jobId: String(job.id) };
}

async function handleOrchestrationPlaceholder(job: Job<OrchestrationJobData>): Promise<{ ok: true; scanId: string; note: string }> {
  // Foundation only: a real orchestration pipeline (adapter resolution,
  // policy re-check, isolated tool containers) is built in later phases.
  logger.info("orchestration placeholder received — no tools executed in this phase", {
    jobId: job.id, scanId: job.data.scanId, assessmentId: job.data.assessmentId,
  });
  await new Promise((resolve) => setTimeout(resolve, 100));
  return { ok: true, scanId: job.data.scanId, note: "placeholder only; scanner orchestration arrives in a later phase" };
}

const placeholderWorker = new Worker(QUEUES.PLACEHOLDER, handlePlaceholder, { connection });
const orchestrationWorker = new Worker(QUEUES.ORCHESTRATION, handleOrchestrationPlaceholder, { connection });

for (const w of [placeholderWorker, orchestrationWorker]) {
  w.on("failed", (job, err) => logger.error("job failed", { jobId: job?.id, error: err.message }));
  w.on("error", (err) => logger.error("worker error", { error: err.message }));
}

const heartbeat = setInterval(() => {
  const health: WorkerHealth = {
    status: redisConnected ? "ok" : "degraded",
    redis: redisConnected ? "connected" : "disconnected",
    queues: [QUEUES.PLACEHOLDER, QUEUES.ORCHESTRATION],
    at: new Date().toISOString(),
  };
  reportHealth(health);
}, 15_000);
heartbeat.unref?.();

logger.info("worker started", { queues: [QUEUES.PLACEHOLDER, QUEUES.ORCHESTRATION] });

async function shutdown(signal: string): Promise<void> {
  logger.info("worker shutting down", { signal });
  clearInterval(heartbeat);
  await Promise.allSettled([placeholderWorker.close(), orchestrationWorker.close()]);
  connection.disconnect();
  process.exit(0);
}
process.on("SIGTERM", () => void shutdown("SIGTERM"));
process.on("SIGINT", () => void shutdown("SIGINT"));
