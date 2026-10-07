import type { StageJobData } from "./executors/stage-executor";

/**
 * Job contracts consumed by the worker. Payloads carry IDs/references ONLY
 * (Prompt 4 §14): workers load trusted state from the database. There is no
 * generic "run command" job and no payload may contain credentials, tokens or
 * scanner output.
 */
export interface PlaceholderJobData {
  kind: "PLACEHOLDER_TEST";
  requestedBy?: string;
  note?: string;
}

/** Scan-level orchestration job: drives the persisted plan's DAG (DagRunner). */
export interface ScanOrchestrationJobData {
  kind: "SCAN_ORCHESTRATION";
  scanId: string;
  workspaceId: string;
}

/** Prompt 11 §55: targeted retest job — IDs only, like every other job. */
export interface RetestJobData {
  kind: "RETEST_EXECUTION";
  retestId: string;
  workspaceId: string;
}

/** @deprecated Phase 2 placeholder shape, kept so old queued jobs fail safe. */
export interface OrchestrationJobData {
  kind: "ASSESSMENT_ORCHESTRATION_PLACEHOLDER";
  scanId: string;
  assessmentId: string;
  workspaceId: string;
}

export type { StageJobData };
