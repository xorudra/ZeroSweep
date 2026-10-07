import { Injectable, OnModuleDestroy } from "@nestjs/common";
import { Queue } from "bullmq";
import IORedis from "ioredis";
import { loadEnv, QUEUES } from "@dsrclone/config";
import { createLogger } from "@dsrclone/logger";

const logger = createLogger("dsrclone-api");

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

  async onModuleDestroy(): Promise<void> {
    await Promise.allSettled([this.placeholder?.close(), this.orchestration?.close(), this.scanOrchestration?.close(), this.retestQueue?.close(), this.validationQueue?.close()]);
    this.connection?.disconnect();
  }
}
