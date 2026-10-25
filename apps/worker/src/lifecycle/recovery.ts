import { prisma } from "@zerosweep/database";
import { reconcileStaleExecution } from "@zerosweep/orchestration";
import { createLogger } from "@zerosweep/logger";

const logger = createLogger("zerosweep-worker");

/**
 * Restart recovery (Prompt 4 §51): on startup, reconcile executions left
 * mid-flight by a previous process. Completed work is NEVER re-run; work on a
 * still-live worker is left alone; orphaned work is requeued (if it never
 * started) or marked failed/timed-out honestly.
 */
export async function recoverStaleExecutions(now = new Date()): Promise<{ requeued: number; failed: number; timedOut: number; left: number }> {
  const stale = await prisma.toolExecution.findMany({
    where: { status: { in: ["QUEUED", "PREPARING", "RUNNING", "PARSING", "NORMALIZING"] } },
    take: 500,
  });
  let requeued = 0, failed = 0, timedOut = 0, left = 0;
  for (const exec of stale) {
    const worker = exec.worker
      ? await prisma.workerNode.findUnique({ where: { workerId: exec.worker } }).catch(() => null)
      : null;
    const action = reconcileStaleExecution({
      id: exec.id, status: exec.status, workerId: exec.worker,
      workerLastHeartbeatAt: worker?.lastHeartbeat ?? null,
      startedAt: exec.startedAt, timeoutSeconds: exec.timeoutSeconds,
    }, now);
    switch (action) {
      case "REQUEUE":
        await prisma.toolExecution.update({ where: { id: exec.id }, data: { status: "QUEUED" } });
        requeued++;
        break;
      case "MARK_FAILED":
        await prisma.toolExecution.update({ where: { id: exec.id }, data: { status: "FAILED", completedAt: now, error: "Worker lost — execution unrecoverable after restart" } });
        failed++;
        break;
      case "MARK_TIMED_OUT":
        await prisma.toolExecution.update({ where: { id: exec.id }, data: { status: "TIMED_OUT", completedAt: now, error: "Execution exceeded timeout before restart" } });
        timedOut++;
        break;
      default:
        left++;
    }
  }
  if (stale.length > 0) logger.info("startup recovery reconciled stale executions", { requeued, failed, timedOut, left });
  return { requeued, failed, timedOut, left };
}
