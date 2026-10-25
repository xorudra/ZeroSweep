import { Injectable, OnModuleDestroy } from "@nestjs/common";
import { Queue } from "bullmq";
import IORedis from "ioredis";
import { loadEnv, QUEUES } from "@zerosweep/config";
import { createLogger } from "@zerosweep/logger";
import { operatorRetryAllowed } from "@zerosweep/security-sdk";

const logger = createLogger("zerosweep-api");

/**
 * Queue access for job CREATION only. The API never executes tools; workers
 * consume jobs. If Redis is unavailable the request still succeeds and the
 * failure is logged — the scan record remains QUEUED in Postgres.
 */
@Injectable()
export class QueueService implements OnModuleDestroy {
  private connection?: IORedis;
  private placeholder?: Queue;
  private orchestration?: Queue;

  private ensure(): { placeholder: Queue; orchestration: Queue } {
    if (!this.connection) {
      this.connection = new IORedis(loadEnv().REDIS_URL, { maxRetriesPerRequest: null, lazyConnect: true });
      this.connection.on("error", (e) => logger.warn("redis error in queue service", { error: e.message }));
      this.placeholder = new Queue(QUEUES.PLACEHOLDER, { connection: this.connection });
      this.orchestration = new Queue(QUEUES.ORCHESTRATION, { connection: this.connection });
    }
    return { placeholder: this.placeholder!, orchestration: this.orchestration! };
  }

  async enqueuePlaceholder(requestedBy: string): Promise<boolean> {
    try {
      const { placeholder } = this.ensure();
      await placeholder.add("placeholder-test", { kind: "PLACEHOLDER_TEST", requestedBy }, { removeOnComplete: 100 });
      return true;
    } catch (e) {
      logger.warn("could not enqueue placeholder job", { error: e instanceof Error ? e.message : "unknown" });
      return false;
    }
  }

  async enqueueOrchestrationPlaceholder(data: { scanId: string; assessmentId: string; workspaceId: string }): Promise<boolean> {
    try {
      const { orchestration } = this.ensure();
      await orchestration.add("assessment-orchestration-placeholder", { kind: "ASSESSMENT_ORCHESTRATION_PLACEHOLDER", ...data }, { removeOnComplete: 100 });
      return true;
    } catch (e) {
      logger.warn("could not enqueue orchestration placeholder", { error: e instanceof Error ? e.message : "unknown" });
      return false;
    }
  }

  private scanOrchestration?: Queue;

  /** Prompt 4: enqueue the scan-orchestration job (IDs only — the worker
   *  loads trusted state from Postgres). Job id == scanId, so a duplicate
   *  start request can never queue the same scan twice. */
  async enqueueScanOrchestration(data: { scanId: string; workspaceId: string }): Promise<boolean> {
    try {
      if (!this.connection) this.ensure();
      if (!this.scanOrchestration) {
        this.scanOrchestration = new Queue(QUEUES.SCAN_ORCHESTRATION, { connection: this.connection! });
      }
      await this.scanOrchestration.add(
        "scan-orchestration",
        { kind: "SCAN_ORCHESTRATION", scanId: data.scanId, workspaceId: data.workspaceId },
        { jobId: `scan-${data.scanId}`, removeOnComplete: 100, removeOnFail: 100 },
      );
      return true;
    } catch (e) {
      logger.warn("could not enqueue scan orchestration", { error: e instanceof Error ? e.message : "unknown" });
      return false;
    }
  }

  private retestQueue?: Queue;

  /** Prompt 11 §55: enqueue a targeted retest (IDs only). Failure to
   *  enqueue is logged and reported — the RetestRequest row stays QUEUED
   *  in Postgres and can be re-dispatched; it is never silently dropped. */
  async enqueueRetest(data: { retestId: string; workspaceId: string }): Promise<boolean> {
    try {
      if (!this.connection) this.ensure();
      if (!this.retestQueue) {
        this.retestQueue = new Queue(QUEUES.RETEST_EXECUTION, { connection: this.connection! });
      }
      await this.retestQueue.add(
        "retest-execution",
        { kind: "RETEST_EXECUTION", retestId: data.retestId, workspaceId: data.workspaceId },
        { jobId: `retest-${data.retestId}`, removeOnComplete: 100, removeOnFail: 100 },
      );
      return true;
    } catch (e) {
      logger.warn("could not enqueue retest", { error: e instanceof Error ? e.message : "unknown" });
      return false;
    }
  }

  private validationQueue?: Queue;

  /** Prompt 16 §12: enqueue a controlled validation session (IDs
   *  only). Failure to enqueue is logged and reported — the
   *  ValidationRequest row stays APPROVED in Postgres and can be
   *  re-dispatched; it is never silently dropped. */
  async enqueueValidation(data: { validationRequestId: string; workspaceId: string }): Promise<boolean> {
    try {
      if (!this.connection) this.ensure();
      if (!this.validationQueue) {
        this.validationQueue = new Queue(QUEUES.VALIDATION_EXECUTION, { connection: this.connection! });
      }
      await this.validationQueue.add(
        "validation-execution",
        { kind: "VALIDATION_EXECUTION", validationRequestId: data.validationRequestId, workspaceId: data.workspaceId },
        { jobId: `validation-${data.validationRequestId}`, removeOnComplete: 100, removeOnFail: 100 },
      );
      return true;
    } catch (e) {
      logger.warn("could not enqueue validation", { error: e instanceof Error ? e.message : "unknown" });
      return false;
    }
  }

  // ---- Prompt 38 §198: queue administration plane -------------------
  // Read models + bounded operator actions over the governed queues.
  // Permission checks and audit live in the platform-ops module; this
  // service only touches Redis. Retry is limited to IDs-only job kinds
  // (operatorRetryAllowed) — a retry re-runs the worker's full
  // authorization/scope gates, never bypasses them.
  private adminQueues = new Map<string, Queue>();

  private adminQueue(name: string): Queue {
    if (!Object.values(QUEUES).includes(name as never)) {
      throw new Error(`unknown queue ${name}`);
    }
    if (!this.connection) this.ensure();
    let q = this.adminQueues.get(name);
    if (!q) {
      q = new Queue(name, { connection: this.connection! });
      this.adminQueues.set(name, q);
    }
    return q;
  }

  async adminSnapshot(): Promise<Array<{
    name: string; waiting: number; active: number; completed: number;
    failed: number; delayed: number; paused: boolean; oldestWaitingAgeMs: number | null;
  }>> {
    const out = [];
    for (const name of Object.values(QUEUES)) {
      try {
        const q = this.adminQueue(name);
        const [counts, waiting] = await Promise.all([
          q.getJobCounts("waiting", "active", "completed", "failed", "delayed"),
          q.getWaiting(0, 0),
        ]);
        out.push({
          name,
          waiting: counts.waiting ?? 0, active: counts.active ?? 0,
          completed: counts.completed ?? 0, failed: counts.failed ?? 0,
          delayed: counts.delayed ?? 0, paused: await q.isPaused(),
          oldestWaitingAgeMs: waiting[0]?.timestamp ? Date.now() - waiting[0].timestamp : null,
        });
      } catch {
        out.push({ name, waiting: 0, active: 0, completed: 0, failed: 0, delayed: 0, paused: false, oldestWaitingAgeMs: null });
      }
    }
    return out;
  }

  async adminFailedJobs(name: string, limit = 25): Promise<Array<{
    id: string; kind: string; attemptsMade: number; failedReason: string;
  }>> {
    const q = this.adminQueue(name);
    const jobs = await q.getFailed(0, Math.min(limit, 100) - 1);
    return jobs.map((j) => ({
      id: String(j.id),
      kind: typeof (j.data as { kind?: unknown })?.kind === "string" ? (j.data as { kind: string }).kind : j.name,
      attemptsMade: j.attemptsMade,
      failedReason: (j.failedReason ?? "unknown").slice(0, 300),
    }));
  }

  /** Returns the job kind when the retry/cancel was applied, or a
   *  refusal reason. Cancelling an ACTIVE job is refused — workers own
   *  in-flight jobs via their leases (§45). */
  async adminRetryJob(name: string, jobId: string): Promise<{ ok: boolean; kind?: string; reason?: string }> {
    const q = this.adminQueue(name);
    const job = await q.getJob(jobId);
    if (!job) return { ok: false, reason: "job not found" };
    const kind = typeof (job.data as { kind?: unknown })?.kind === "string" ? (job.data as { kind: string }).kind : job.name;
    if (!operatorRetryAllowed(kind)) return { ok: false, reason: `job kind ${kind} is not operator-retryable (§198)` };
    const state = await job.getState();
    if (state !== "failed") return { ok: false, reason: `only failed jobs can be retried (state: ${state})` };
    await job.retry();
    return { ok: true, kind };
  }

  async adminCancelJob(name: string, jobId: string): Promise<{ ok: boolean; kind?: string; reason?: string }> {
    const q = this.adminQueue(name);
    const job = await q.getJob(jobId);
    if (!job) return { ok: false, reason: "job not found" };
    const kind = typeof (job.data as { kind?: unknown })?.kind === "string" ? (job.data as { kind: string }).kind : job.name;
    const state = await job.getState();
    if (state === "active") return { ok: false, reason: "active jobs are owned by their worker lease and cannot be cancelled from the admin plane (§45)" };
    if (state === "completed") return { ok: false, reason: "completed jobs cannot be cancelled" };
    await job.remove();
    return { ok: true, kind };
  }

  async onModuleDestroy(): Promise<void> {
    await Promise.allSettled([this.placeholder?.close(), this.orchestration?.close(), this.scanOrchestration?.close(), this.retestQueue?.close(), this.validationQueue?.close(), ...[...this.adminQueues.values()].map((q) => q.close())]);
    this.connection?.disconnect();
  }
}
