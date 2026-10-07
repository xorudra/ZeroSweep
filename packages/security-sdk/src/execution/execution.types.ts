import type { NetworkPolicyMode, RiskLevel } from "../adapter/adapter.types";

export interface AuthorizationContext {
  organizationId: string;
  workspaceId: string;
  targetId: string;
  targetOrganizationId: string; // org that owns the target, from trusted DB state
  assessmentId: string;
  scanId: string;
  verificationStatus: "PENDING" | "VERIFIED" | "EXPIRED" | "REJECTED";
  approvalStatus: "NOT_REQUIRED" | "PENDING" | "APPROVED" | "REJECTED";
  scopeId?: string;
  requestedBy: string;
}

/**
 * An ExecutionPlan is generated ONLY by trusted adapter code inside the worker.
 * User input always arrives as individual validated arguments — never as a
 * shell string. There is deliberately no API that accepts a raw command.
 */
export interface ExecutionPlan {
  adapterId: string;
  toolId: string;
  executionMode: string;
  containerImage?: string;
  imageDigest?: string;
  executable?: string;
  arguments: string[];
  environmentReferences: string[]; // secret REFERENCES, never values
  timeoutSeconds: number;
  cpuLimit: string;
  memoryLimit: string;
  networkPolicy: NetworkPolicyMode;
  expectedOutputFormat: string;
  outputFiles: string[];
}

export interface ExecutionLimits {
  maxStdoutBytes: number;
  maxStderrBytes: number;
  maxArtifactBytes: number;
  maxArtifacts: number;
  maxTimeoutSeconds: number;
  requestsPerMinute: number;
  maxConcurrency: number;
}
export const DEFAULT_LIMITS: ExecutionLimits = {
  maxStdoutBytes: 10 * 1024 * 1024,
  maxStderrBytes: 2 * 1024 * 1024,
  maxArtifactBytes: 100 * 1024 * 1024,
  maxArtifacts: 50,
  maxTimeoutSeconds: 3600,
  requestsPerMinute: 60,
  maxConcurrency: 2,
};

export type ExecutionStatus =
  | "QUEUED" | "PREPARING" | "RUNNING" | "CANCELLING" | "CANCELLED"
  | "COMPLETED" | "FAILED" | "TIMED_OUT";

export type RetryCategory = "TRANSIENT" | "CONFIGURATION" | "POLICY" | "TARGET_ERROR" | "TOOL_ERROR" | "TIMEOUT";
export const RETRYABLE: Record<RetryCategory, boolean> = {
  TRANSIENT: true, CONFIGURATION: false, POLICY: false, TARGET_ERROR: false, TOOL_ERROR: false, TIMEOUT: true,
};

export const TOOL_EXECUTION_EVENTS = [
  "TOOL_QUEUED", "TOOL_PREPARING", "TOOL_STARTED", "TOOL_PROGRESS", "TOOL_OUTPUT_RECEIVED",
  "TOOL_PARSING", "TOOL_NORMALIZING", "TOOL_COMPLETED", "TOOL_FAILED", "TOOL_CANCELLED", "TOOL_TIMED_OUT",
] as const;
export type ToolExecutionEvent = (typeof TOOL_EXECUTION_EVENTS)[number];

export interface RiskContext { riskLevel: RiskLevel; }
