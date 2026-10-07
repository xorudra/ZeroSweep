import { Worker, type Job } from "bullmq";
import { QUEUES } from "@dsrclone/config";
import { createLogger } from "@dsrclone/logger";
import { LocalEchoAdapter, MockSecurityAdapter, ToolRegistry, registerApiAdapters, registerCloudNativeAdapters, registerCloudSecAdapters, registerCodeAdapters, registerDirectoryAdapters, registerMobileAdapters, registerNetworkAdapters, registerProxyAdapters, registerReconAdapters, registerVulnAdapters, registerVulnScannerAdapters, registerWebDiscoveryAdapters } from "@dsrclone/security-sdk";
import { prisma } from "@dsrclone/database";
import { createRedisConnection } from "./connection";
import { reportHealth, type WorkerHealth } from "./health";
import type { OrchestrationJobData, PlaceholderJobData, ScanOrchestrationJobData } from "./jobs";
import { StageExecutor, type StageJobData } from "./executors/stage-executor";
import { PrismaWorkerStore } from "./store/prisma-store";
import { prismaScannerDeps } from "./store/scanner-deps";
import { prismaKubernetesDeps } from "./store/kubernetes-deps";
import { prismaCloudDeps } from "./store/cloud-deps";
import { prismaDirectoryDeps } from "./store/directory-deps";
import { prismaMobileDeps } from "./store/mobile-deps";
import { RetestRunner } from "./executors/retest-runner";
import type { RetestJobData, ValidationJobData } from "./jobs";
import { UnconfiguredValidationTransport, ValidationRunner } from "./executors/validation-runner";
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
// Prompt 12: source code security adapters (Semgrep / CodeQL / Bandit /
// Brakeman / SpotBugs / Gitleaks / TruffleHog / Dependency-Check / Grype)
// plus the SonarQube connector over the same admin-registered instance
// discipline. Source tools analyze snapshots read-only with NO_NETWORK;
// absent binaries report UNAVAILABLE honestly (§2/§13/§14).
registerCodeAdapters(registry, undefined, prismaScannerDeps());
// Prompt 13: cloud-native adapters (Syft / Trivy / Checkov / Kubescape /
// kube-hunter + the INTERNAL_PRIVILEGED Docker Bench / kube-bench pair)
// and the Kubernetes connector over Prisma-resolved cluster records.
// Images are analyzed statically — never executed (§9); the privileged
// pair is executor-gated on PRIVILEGED_HOST_ASSESSMENT (§28/§39), and
// the connector's live transport honestly reports UNAVAILABLE until a
// read-only cluster client is provisioned on the worker (§34).
registerCloudNativeAdapters(registry, undefined, prismaKubernetesDeps());
// Prompt 14: multi-cloud adapters (provider inventory connectors,
// Prowler / ScoutSuite / Steampipe, CloudMapper / ROADtools imports)
// over Prisma-resolved CloudAccount records. Assessment is READ-ONLY
// forever (§7); accounts without a wired provider transport report
// NOT_CONFIGURED (§9), and cloud adapters execute only on
// CLOUD_ANALYSIS workers (§10). Pacu is registered DISABLED in the
// catalog only — it has no adapter and never executes (§34).
registerCloudSecAdapters(registry, undefined, prismaCloudDeps());
// Prompt 15: Active Directory adapters (LDAP/BloodHound connectors,
// ldapsearch/SharpHound/PingCastle/enum4linux-ng/SMBMap/Certipy-find)
// over Prisma-resolved domain records. Collection is READ-ONLY (§7);
// live directory transports report NOT_CONFIGURED until provisioned
// on a DIRECTORY_ANALYSIS worker (§10), and the offensive family has
// no adapters at all (§103).
registerDirectoryAdapters(registry, undefined, prismaDirectoryDeps());
// Prompt 17: mobile adapters (MobSF connector, JADX, apktool, Ghidra
// + the controlled-lab ADB/mitmproxy adapters) over Prisma-resolved
// application/build records. Static analysis runs in the sandbox —
// app code is never executed (§8); dynamic adapters execute only on
// MOBILE_DYNAMIC_ANALYSIS workers with an approved lab session, and
// their transports report NOT_CONFIGURED until a lab is provisioned
// (§58). Frida/Objection have NO adapters (§69–§74).
registerMobileAdapters(registry, undefined, prismaMobileDeps());
const executor = new StageExecutor(registry, store, undefined, {
  workerCapabilities: privilegedCapabilitiesFromEnv(),
});
const runner = new DagRunner(store, executor);
const retestRunner = new RetestRunner(store, executor);

async function handleRetest(job: Job<RetestJobData>): Promise<{ ok: true; retestId: string; status: string; outcome?: string }> {
  const result = await retestRunner.runRetest(job.data.retestId);
  return { ok: true, retestId: job.data.retestId, ...result };
}

async function handleValidation(job: Job<ValidationJobData>): Promise<{ ok: true; validationRequestId: string; status: string; outcome?: string; reasonCode?: string }> {
  const result = await validationRunner.runValidation(job.data.validationRequestId);
  return { ok: true, validationRequestId: job.data.validationRequestId, ...result };
}
const workerId = makeWorkerId();
// Prompt 16 §45/§46: validation runs ONLY on worker processes, under
// the full re-check gauntlet in ValidationRunner. The transport is
// deliberately unconfigured until a deployment provisions governed
// egress transports — sessions then fail honestly rather than
// fabricating results.
const validationRunner = new ValidationRunner(store, new UnconfiguredValidationTransport(), { workerId });
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
  new Worker(QUEUES.VALIDATION_EXECUTION, handleValidation, { connection, concurrency: 2 }),
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
