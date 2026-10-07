import { Queue } from "bullmq";
import type IORedis from "ioredis";
import { prisma } from "@dsrclone/database";
import { stageJobId } from "@dsrclone/orchestration";
import type { StageDispatcher } from "./dag-runner";
import type { StageJobData, StageExecutionOutcome } from "../executors/stage-executor";

/**
 * Production stage dispatcher (Prompt 4 §13–§15): enqueues the stage job on
 * the stage-execution queue with a deterministic BullMQ job id (duplicate
 * dispatch = same job id = no duplicate execution), then waits on the
 * ToolExecution record — the database, not Redis, is the source of truth.
 */
export function createBullmqStageDispatcher(connection: IORedis, queueName: string): { dispatch: StageDispatcher; close: () => Promise<void> } {
  const queue = new Queue(queueName, { connection });
  const dispatch: StageDispatcher = async (job: StageJobData): Promise<StageExecutionOutcome> => {
    await queue.add("stage-execution", job, {
      jobId: stageJobId(job.scanId, job.stageId, job.attempt),
      removeOnComplete: 100,
      removeOnFail: 100,
      attempts: 1, // retry policy is owned by the orchestration layer (§29), not BullMQ blind retries
    });
    const deadline = Date.now() + 30 * 60 * 1000;
    for (;;) {
      const exec = await prisma.toolExecution.findUnique({ where: { id: job.toolExecutionId }, select: { status: true } });
      if (!exec) return { status: "FAILED", category: "CONFIGURATION" };
      switch (exec.status) {
        case "COMPLETED": {
          const metrics = await prisma.toolExecution.findUnique({ where: { id: job.toolExecutionId }, select: { metrics: true } });
          const m = (metrics?.metrics ?? {}) as { assets?: number; findings?: number };
          return { status: "COMPLETED", assets: m.assets ?? 0, findings: m.findings ?? 0 };
        }
        case "CANCELLED": return { status: "CANCELLED" };
        case "TIMED_OUT": return { status: "TIMED_OUT", category: "TIMEOUT" };
        case "FAILED": return { status: "FAILED", category: "TOOL_ERROR" };
        default: break;
      }
      if (Date.now() > deadline) return { status: "TIMED_OUT", category: "TIMEOUT" };
      await new Promise((r) => setTimeout(r, 500));
    }
  };
  return { dispatch, close: () => queue.close() };
}
