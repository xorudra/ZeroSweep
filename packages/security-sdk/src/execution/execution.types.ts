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
  /** Data-only standard input (e.g. the authorized host list for dnsx /
   *  waybackurls). Carries validated target values, never commands. */
  stdin?: string;
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

/**
 * Container execution contract (Prompt 3 §12). Defaults are the secure
 * posture: non-root, read-only root filesystem, no privileged mode, no host
 * networking, no Docker socket, all capabilities dropped, tmpfs workspace.
 */
export interface ContainerExecutionSpec {
  image: string;
  imageDigest?: string;
  entrypoint?: string;
  args: string[];
  environmentReferences: string[]; // secret REFERENCES resolved inside the worker only
  runAsNonRoot: boolean;
  readOnlyRootFilesystem: boolean;
  privileged: boolean;
  networkMode: NetworkPolicyMode;
  cpuLimit: string;
  memoryLimit: string;
  pidsLimit: number;
  timeoutSeconds: number;
  workingDirectory: string;
  mountedInputs: string[];
  mountedOutputs: string[];
  dropCapabilities: string[]; // ["ALL"] by default
}

export function defaultContainerSpec(partial: Partial<ContainerExecutionSpec> & { image: string; args: string[] }): ContainerExecutionSpec {
  return {
    entrypoint: undefined, environmentReferences: [], runAsNonRoot: true,
    readOnlyRootFilesystem: true, privileged: false, networkMode: "SCOPE_ONLY",
    cpuLimit: "1", memoryLimit: "512Mi", pidsLimit: 128, timeoutSeconds: 600,
    workingDirectory: "/work", mountedInputs: [], mountedOutputs: [],
    dropCapabilities: ["ALL"], ...partial,
  };
}

/** Execution telemetry (Prompt 3 §38) — counts and timings only, never
 *  secrets, request bodies or raw credentials. */
export interface ExecutionTelemetry {
  executionId: string;
  toolSlug: string;
  queueWaitMs: number;
  durationMs: number;
  exitStatus: ExecutionStatus;
  cpuMillis?: number;
  memoryPeakBytes?: number;
  stdoutBytes: number;
  stderrBytes: number;
  artifactBytes: number;
  findingCount: number;
  assetCount: number;
}

export interface ExecutionResult {
  status: ExecutionStatus;
  exitCode?: number;
  telemetry: ExecutionTelemetry;
  rawArtifactIds: string[];
  errorCategory?: RetryCategory;
  errorMessage?: string; // sanitized — safe for API display
}

export interface ExecutionEventRecord {
  type: ToolExecutionEvent;
  executionId: string;
  scanId: string;
  at: string; // ISO timestamp
  detail?: string;
}
