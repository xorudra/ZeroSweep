import { hostname } from "node:os";
import { workerStatusFromHeartbeat, type WorkerStatus } from "@dsrclone/orchestration";

/**
 * Worker registration + heartbeat (Prompt 4 §21–§23). The worker registers a
 * WorkerNode row on startup and refreshes lastHeartbeat on an interval;
 * status is DERIVED from heartbeat age against configurable thresholds, so a
 * single missed beat never marks a worker offline.
 */

export const WORKER_VERSION = "0.4.0";

/** Capabilities this worker advertises. In this phase it can execute only the
 *  mock/echo simulation adapters, for stages requiring these capabilities. */
export const WORKER_CAPABILITIES = [
  "SUBDOMAIN_DISCOVERY", "DNS_RESOLUTION", "HTTP_PROBING", "TECHNOLOGY_DETECTION",
  "WEB_CRAWLING", "URL_DISCOVERY", "PARAMETER_DISCOVERY", "VULNERABILITY_SCANNING",
  "REPORT_EXPORT",
];

export function makeWorkerId(): string {
  return `worker-${hostname()}-${process.pid}`;
}

export interface WorkerRegistration {
  workerId: string;
  hostname: string;
  version: string;
  status: WorkerStatus;
  capabilities: string[];
  activeJobs: number;
  startedAt: Date;
  lastHeartbeat: Date;
}

export function registrationRecord(workerId: string, activeJobs: number, now = new Date()): WorkerRegistration {
  return {
    workerId,
    hostname: hostname(),
    version: WORKER_VERSION,
    status: workerStatusFromHeartbeat({ lastHeartbeatAt: now, now, activeJobs, capacity: 4 }),
    capabilities: WORKER_CAPABILITIES,
    activeJobs,
    startedAt: now,
    lastHeartbeat: now,
  };
}
