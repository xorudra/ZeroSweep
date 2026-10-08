/**
 * Prompt 38 — Production Deployment, Observability & Operations V2.
 * Shared platform-operations vocabulary: RBAC permissions (§203), audit
 * actions (§204), operator kill switches (§158), queue classes (§40) and
 * worker types (§47). Pure data + types; behaviour lives in the sibling
 * modules and in the API platform-ops services.
 */

export const PLATFORM_PERMISSIONS = [
  "VIEW_PLATFORM_HEALTH",
  "VIEW_PLATFORM_METRICS",
  "MANAGE_QUEUES",
  "MANAGE_WORKERS",
  "MANAGE_PLATFORM_CONFIG",
  "MANAGE_BACKUPS",
  "RUN_RESTORE",
  "MANAGE_MAINTENANCE",
  "MANAGE_DEPLOYMENTS",
] as const;
export type PlatformPermission = (typeof PLATFORM_PERMISSIONS)[number];

export const PLATFORM_AUDIT_ACTIONS = [
  "PLATFORM_MAINTENANCE_ENABLED",
  "PLATFORM_MAINTENANCE_DISABLED",
  "SCAN_KILL_SWITCH_ENABLED",
  "SCAN_KILL_SWITCH_DISABLED",
  "BACKUP_STARTED",
  "BACKUP_COMPLETED",
  "BACKUP_FAILED",
  "RESTORE_STARTED",
  "RESTORE_COMPLETED",
  "RESTORE_FAILED",
  "QUEUE_JOB_RETRIED",
  "QUEUE_JOB_CANCELLED",
  "PRODUCTION_DEPLOYMENT_STARTED",
  "PRODUCTION_DEPLOYMENT_COMPLETED",
  "PRODUCTION_ROLLBACK_STARTED",
] as const;
export type PlatformAuditAction = (typeof PLATFORM_AUDIT_ACTIONS)[number];

/** Operator kill switches (§158): each halts ONE work class without
 *  shutting the platform down. Reads, health and the admin plane itself
 *  are never switched off. */
export const KILL_SWITCHES = [
  "SCAN_STARTS",
  "AI_WORKFLOWS",
  "INTEGRATION_SYNC",
  "REPORT_JOBS",
] as const;
export type KillSwitch = (typeof KILL_SWITCHES)[number];

export interface KillSwitchState {
  enabled: boolean;
  reason?: string;
  setById?: string;
  setAt?: string;
}

export interface PlatformControlState {
  maintenanceMode: boolean;
  maintenanceMessage?: string;
  killSwitches: Partial<Record<KillSwitch, KillSwitchState>>;
}

/** Queue classes (§40): work is separated so a flood of cheap jobs can
 *  never starve scan execution, and scanner classes scale independently
 *  (§75). Names map onto the platform's governed BullMQ queues. */
export const QUEUE_CLASSES = [
  "general",
  "recon",
  "web-scan",
  "network-scan",
  "cloud-scan",
  "container-scan",
  "mobile-analysis",
  "binary-analysis",
  "report-generation",
  "ai-jobs",
  "notifications",
  "integration-sync",
] as const;
export type QueueClass = (typeof QUEUE_CLASSES)[number];

/** Worker types (§47). Scanner classes are isolated from the control
 *  plane (§50); privileged tools belong ONLY to PRIVILEGED_HOST (§51). */
export const WORKER_TYPES = [
  "GENERAL_WORKER",
  "RECON_WORKER",
  "WEB_VAPT_WORKER",
  "NETWORK_VAPT_WORKER",
  "CLOUD_WORKER",
  "CONTAINER_WORKER",
  "MOBILE_WORKER",
  "BINARY_WORKER",
  "REPORT_WORKER",
  "AI_WORKER",
  "PRIVILEGED_HOST",
] as const;
export type WorkerType = (typeof WORKER_TYPES)[number];

export type BackupKind = "POSTGRES" | "OBJECT_STORAGE" | "CONFIG_METADATA" | "FULL";
export type BackupStatus = "STARTED" | "COMPLETED" | "FAILED";
export type RestoreStatus = "STARTED" | "COMPLETED" | "FAILED";
export type DeploymentStatus =
  | "STARTED" | "COMPLETED" | "FAILED" | "ROLLBACK_STARTED" | "ROLLED_BACK";

export interface ReleaseMetadata {
  version: string;
  commit: string;
  build?: string;
  migrationVersion?: string;
  deployedAt?: string;
  environment: string;
}
