/**
 * Job contracts consumed by the worker. In this phase the ONLY job is a
 * harmless placeholder that proves the queue pipeline end-to-end:
 * receive job -> log its id -> wait briefly -> complete.
 * No security tool is executed here, and there is no generic "run command" job.
 */
export interface PlaceholderJobData {
  kind: "PLACEHOLDER_TEST";
  requestedBy?: string;
  note?: string;
}

export interface OrchestrationJobData {
  kind: "ASSESSMENT_ORCHESTRATION_PLACEHOLDER";
  scanId: string;
  assessmentId: string;
  workspaceId: string;
}
