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
  // Prompt 10 §23: external network capabilities are safe to advertise on
  // any network-capable worker. LOCAL_NETWORK_DISCOVERY and
  // PACKET_CAPTURE are NEVER in the base set — they arrive only through
  // the deployment env of a dedicated internal / packet-analysis worker.
  "HOST_DISCOVERY", "PORT_DISCOVERY", "SERVICE_DETECTION", "VERSION_DETECTION",
  "OS_HINTING", "SAFE_NETWORK_CHECKS",
];

/** Prompt 10 §23/§24: worker types. The type + privileged capabilities
 *  come from the worker's OWN deployment environment — a general worker
 *  cannot promote itself, and job payloads never carry them. */
export const WORKER_TYPES = ["GENERAL_WEB", "NETWORK_EXTERNAL", "NETWORK_INTERNAL", "PACKET_ANALYSIS", "CONTAINER_ANALYSIS", "PRIVILEGED_HOST", "CLOUD_ANALYSIS", "DIRECTORY_ANALYSIS"] as const;
export type WorkerTypeName = (typeof WORKER_TYPES)[number];

export function workerTypeFromEnv(env: NodeJS.ProcessEnv = process.env): WorkerTypeName {
  const raw = (env.DSRCLONE_WORKER_TYPE ?? "GENERAL_WEB").toUpperCase();
  return (WORKER_TYPES as readonly string[]).includes(raw) ? (raw as WorkerTypeName) : "GENERAL_WEB";
}

export function privilegedCapabilitiesFromEnv(env: NodeJS.ProcessEnv = process.env): string[] {
  const type = workerTypeFromEnv(env);
  const declared = (env.DSRCLONE_WORKER_CAPABILITIES ?? "")
    .split(",").map((s) => s.trim().toUpperCase()).filter(Boolean);
  const allowed = new Set<string>();
  // Layer-2 access exists only on internal workers; packet capture only
  // on packet-analysis workers — the env of the WRONG type cannot grant
  // them (§24/§65).
  if (type === "NETWORK_INTERNAL" && declared.includes("LOCAL_LAYER2_ACCESS")) {
    allowed.add("LOCAL_LAYER2_ACCESS");
    allowed.add("LOCAL_NETWORK_DISCOVERY");
  }
  if (type === "PACKET_ANALYSIS" && declared.includes("PACKET_CAPTURE")) {
    allowed.add("PACKET_CAPTURE");
    allowed.add("PACKET_ANALYSIS");
  }
  // Prompt 13 §10/§28/§39: container analysis is an isolated worker
  // type; privileged benchmark assessment (Docker Bench / kube-bench)
  // exists only on PRIVILEGED_HOST workers that declare it — the env
  // of any other worker type cannot grant it.
  if (type === "CONTAINER_ANALYSIS" && declared.includes("CONTAINER_ANALYSIS")) {
    allowed.add("CONTAINER_ANALYSIS");
  }
  if (type === "PRIVILEGED_HOST" && declared.includes("PRIVILEGED_HOST_ASSESSMENT")) {
    allowed.add("PRIVILEGED_HOST_ASSESSMENT");
  }
  // Prompt 14 §10: cloud credentials are issued ONLY to CLOUD_ANALYSIS
  // workers — the env of any other worker type cannot grant it.
  if (type === "CLOUD_ANALYSIS" && declared.includes("CLOUD_ANALYSIS")) {
    allowed.add("CLOUD_ANALYSIS");
  }
  // Prompt 15 §10/§11: directory collection runs ONLY on
  // DIRECTORY_ANALYSIS workers — the env of any other worker type
  // cannot grant it.
  if (type === "DIRECTORY_ANALYSIS" && declared.includes("DIRECTORY_ANALYSIS")) {
    allowed.add("DIRECTORY_ANALYSIS");
  }
  return [...allowed];
}

export function workerCapabilitiesFromEnv(env: NodeJS.ProcessEnv = process.env): string[] {
  return [...new Set([...WORKER_CAPABILITIES, ...privilegedCapabilitiesFromEnv(env)])];
}

export function makeWorkerId(): string {
  return `worker-${hostname()}-${process.pid}`;
}

export interface WorkerRegistration {
  workerId: string;
  hostname: string;
  version: string;
  workerType: string;
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
    workerType: workerTypeFromEnv(),
    status: workerStatusFromHeartbeat({ lastHeartbeatAt: now, now, activeJobs, capacity: 4 }),
    capabilities: workerCapabilitiesFromEnv(),
    activeJobs,
    startedAt: now,
    lastHeartbeat: now,
  };
}
