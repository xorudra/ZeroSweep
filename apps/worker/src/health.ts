import { writeFileSync } from "node:fs";
import { createLogger } from "@zerosweep/logger";

const logger = createLogger("zerosweep-worker");

export interface WorkerHealth {
  status: "ok" | "degraded";
  redis: "connected" | "disconnected";
  queues: string[];
  at: string;
}

/** Workers have no HTTP surface in this phase: health is logged and written
 *  to a heartbeat file the dashboard/API can read. */
export function reportHealth(health: WorkerHealth): void {
  const file = process.env.WORKER_HEARTBEAT_FILE ?? "/tmp/zerosweep-worker-heartbeat.json";
  try {
    writeFileSync(file, JSON.stringify(health, null, 2));
  } catch {
    // heartbeat file is best-effort; the structured log line is the fallback
  }
  logger.info("worker health", { ...health });
}
