import { Worker, type Job } from "bullmq";
import { QUEUES } from "@dsrclone/config";
import { createLogger } from "@dsrclone/logger";
import { LocalEchoAdapter, MockSecurityAdapter, ToolRegistry, registerApiAdapters, registerNetworkAdapters, registerProxyAdapters, registerReconAdapters, registerVulnAdapters, registerVulnScannerAdapters, registerWebDiscoveryAdapters } from "@dsrclone/security-sdk";
import { prisma } from "@dsrclone/database";
import { createRedisConnection } from "./connection";
import { reportHealth, type WorkerHealth } from "./health";
import type { OrchestrationJobData, PlaceholderJobData, ScanOrchestrationJobData } from "./jobs";
import { StageExecutor, type StageJobData } from "./executors/stage-executor";
import { PrismaWorkerStore } from "./store/prisma-store";
import { prismaScannerDeps } from "./store/scanner-deps";
import { RetestRunner } from "./executors/retest-runner";
import type { RetestJobData } from "./jobs";
import { DagRunner } from "./consumers/dag-runner";
import { createBullmqStageDispatcher } from "./consumers/bullmq-dispatcher";
import { makeWorkerId, privilegedCapabilitiesFromEnv, registrationRecord } from "./heartbeat/heartbeat";
import { recoverStaleExecutions } from "./lifecycle/recovery";
import { metrics, METRICS } from "./telemetry/metrics";

/**
 * DSRclone worker (Prompt 4 §20–§23, §52): production queue consumer.
 * Registers a WorkerNode, heartbeats, consumes scan-orchestration jobs and
 * drives each plan's DAG — dispatching stage-execution jobs (IDs only) that
 * re-evaluate authorization/scope/policy before running an adapter.
 * Executable adapters: mock + local-echo (simulation/diagnostics) and the
 * Prompt 5 recon adapters. A recon adapter whose binary is absent from the
 * worker host reports UNAVAILABLE and is never executed — the DAG degrades
 * the capability instead (Prompt 5 §2/§56).
 */

const logger = createLogger("dsrclone-worker");
const connection = createRedisConnection();
const store = new PrismaWorkerStore();
const registry = new ToolRegistry();
registry.register(new MockSecurityAdapter());
registry.register(new LocalEchoAdapter());
registerReconAdapters(registry);
registerWebDiscoveryAdapters(registry);
registerVulnAdapters(registry);
// Prompt 8: interactive scanner connectors (ZAP / Burp / Caido) backed by
// admin-registered ScannerInstance rows. With none registered they report
// NOT_CONFIGURED and the passive stage is honestly skipped (§66).
registerProxyAdapters(registry, prismaScannerDeps());
// Prompt 11 §84: vulnerability scanner connectors (Greenbone / Nessus)
// for the network profiles' optional vulnerability stage. Unconfigured
// they report NOT_CONFIGURED and the stage is honestly skipped (§85/§86).
registerVulnScannerAdapters(registry, prismaScannerDeps());
// Prompt 9: API security adapters (Kiterunner / Schemathesis / InQL /
// GraphQLmap + the jwt_tool inspection adapter). Binaries absent from
// the worker host report UNAVAILABLE and are never executed (§2).
registerApiAdapters(registry);
// Prompt 10: network VAPT adapters (Nmap / Naabu / RustScan / Masscan /
// Netdiscover / arp-scan / tcpdump / tshark). The executor gates the
// privileged ones on THIS worker's own deployment capabilities (§65):
// local layer-2 discovery and packet capture exist only when the
// worker's env grants them (internal / packet-analysis workers).
registerNetworkAdapters(registry);
const executor = new StageExecutor(registry, store, undefined, {
  workerCapabilities: privilegedCapabilitiesFromEnv(),
});
const runner = new DagRunner(store, executor);
const retestRunner = new RetestRunner(store, executor);

async function handleRetest(job: Job<RetestJobData>): Promise<{ ok: true; retestId: string; status: string; outcome?: string }> {
  const result = await retestRunner.runRetest(job.data.retestId);
  return { ok: true, retestId: job.data.retestId, ...result };
}
const workerId = makeWorkerId();
let activeJobs = 0;
let draining = false;

let redisConnected = false;
connection.on("ready", () => { redisConnected = true; logger.info("redis connected"); });
connection.on("error", (err) => { redisConnected = false; logger.error("redis connection error", { error: err.message }); });

async function handlePlaceholder(job: Job<PlaceholderJobData>): Promise<{ ok: true; jobId: string }> {
  logger.info("placeholder job received", { jobId: job.id, kind: job.data.kind });
  await new Promise((resolve) => setTimeout(resolve, 250));
  return { ok: true, jobId: String(job.id) };
}

async function handleScanOrchestration(job: Job<ScanOrchestrationJobData | OrchestrationJobData>): Promise<{ ok: true; scanId: string; status?: string }> {
  if (job.data.kind !== "SCAN_ORCHESTRATION") {
    // Legacy Phase 2 placeholder jobs: acknowledge without executing anything.
    logger.warn("legacy orchestration placeholder job ignored", { jobId: job.id, scanId: job.data.scanId });
    return { ok: true, scanId: job.data.scanId, status: "IGNORED_LEGACY" };
  }
  if (draining) throw new Error("worker is draining — retry later");
  activeJobs++;
  metrics.inc(METRICS.scansQueued);
  const started = Date.now();
  try {
    const { dispatch, close } = createBullmqStageDispatcher(connection, QUEUES.STAGE_EXECUTION);
    try {
      const result = await runner.run(job.data.scanId, dispatch);
      metrics.setGauge(METRICS.scanDurationMs, Date.now() - started);
      if (result.status === "FAILED") metrics.inc(METRICS.failures);
      if (result.status === "CANCELLED") metrics.inc(METRICS.cancellations);
      return { ok: true, scanId: job.data.scanId, status: result.status };
    } finally {
      await close();
    }
  } finally {
    activeJobs--;
  }
}

async function handleStageExecution(job: Job<StageJobData>): Promise<unknown> {
  if (draining) throw new Error("worker is draining — retry later");
  activeJobs++;
  const started = Date.now();
  try {
    const outcome = await executor.run(job.data);
    metrics.setGauge(METRICS.toolExecutionDurationMs, Date.now() - started);
    if (outcome.status === "TIMED_OUT") metrics.inc(METRICS.timeouts);
    return outcome;
  } finally {
    activeJobs--;
  }
}

const workers = [
  new Worker(QUEUES.PLACEHOLDER, handlePlaceholder, { connection }),
  new Worker(QUEUES.SCAN_ORCHESTRATION, handleScanOrchestration, { connection }),
  new Worker(QUEUES.ORCHESTRATION, handleScanOrchestration, { connection }),
  new Worker(QUEUES.STAGE_EXECUTION, handleStageExecution, { connection, concurrency: 4 }),
  new Worker(QUEUES.RETEST_EXECUTION, handleRetest, { connection, concurrency: 2 }),
];
for (const w of workers) {
  w.on("failed", (job, err) => logger.error("job failed", { jobId: job?.id, queue: w.name, error: err.message }));
  w.on("error", (err) => logger.error("worker error", { queue: w.name, error: err.message }));
}

async function registerAndHeartbeat(): Promise<void> {
  const record = registrationRecord(workerId, activeJobs);
  try {
    await prisma.workerNode.upsert({
      where: { workerId },
      create: record,
      update: { lastHeartbeat: record.lastHeartbeat, status: draining ? "DRAINING" : record.status, activeJobs, capabilities: record.capabilities as never, workerType: record.workerType },
    });
  } catch (e) {
    logger.warn("worker registration heartbeat failed (database unavailable?)", { error: e instanceof Error ? e.message : "unknown" });
  }
  const health: WorkerHealth = {
    status: redisConnected ? "ok" : "degraded",
    redis: redisConnected ? "connected" : "disconnected",
    queues: workers.map((w) => w.name),
    at: new Date().toISOString(),
  };
  reportHealth(health);
}

void (async () => {
  await registerAndHeartbeat();
  await recoverStaleExecutions().catch((e) => logger.warn("startup recovery failed", { error: e instanceof Error ? e.message : "unknown" }));
})();
const heartbeat = setInterval(() => void registerAndHeartbeat(), 15_000);
heartbeat.unref?.();

logger.info("worker started", { workerId, queues: workers.map((w) => w.name), executableAdapters: ["mock", "local-echo", "subfinder", "amass", "assetfinder", "findomain", "dnsx", "httpx", "whatweb", "gau", "waybackurls", "katana", "ffuf", "feroxbuster", "gobuster", "wfuzz", "arjun", "nuclei", "nikto", "testssl", "sslyze", "owasp-zap", "burp-suite-professional", "caido"] });

/** Graceful drain (§52): stop taking jobs, let active work finish, flush state. */
async function shutdown(signal: string): Promise<void> {
  if (draining) return;
  draining = true;
  logger.info("worker draining", { signal, activeJobs });
  try {
    await prisma.workerNode.update({ where: { workerId }, data: { status: "DRAINING" } }).catch(() => undefined);
  } catch { /* best effort */ }
  clearInterval(heartbeat);
  const deadline = Date.now() + 30_000;
  while (activeJobs > 0 && Date.now() < deadline) await new Promise((r) => setTimeout(r, 250));
  await Promise.allSettled(workers.map((w) => w.close()));
  connection.disconnect();
  logger.info("worker shutdown complete", { metrics: metrics.snapshot() });
  process.exit(0);
}
process.on("SIGTERM", () => void shutdown("SIGTERM"));
process.on("SIGINT", () => void shutdown("SIGINT"));
