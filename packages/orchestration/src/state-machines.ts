/**
 * Stage and tool-execution state machines (Prompt 4 §18–§19).
 * The scan state machine lives in @zerosweep/types (SCAN_TRANSITIONS); these
 * two complete the trio the orchestration engine enforces everywhere.
 */

export const STAGE_STATUSES = [
  "PENDING", "BLOCKED", "READY", "QUEUED", "RUNNING",
  "COMPLETED", "PARTIAL", "FAILED", "SKIPPED", "CANCELLED",
] as const;
export type StageStatus = (typeof STAGE_STATUSES)[number];

/**
 * Dependencies drive BLOCKED -> READY (all dependencies COMPLETED/PARTIAL/
 * SKIPPED per the stage failure strategy). Terminal states never leave.
 */
export const STAGE_TRANSITIONS: Readonly<Record<StageStatus, readonly StageStatus[]>> = {
  PENDING: ["BLOCKED", "READY", "QUEUED", "SKIPPED", "CANCELLED"],
  BLOCKED: ["READY", "SKIPPED", "CANCELLED"],
  READY: ["QUEUED", "SKIPPED", "CANCELLED"],
  QUEUED: ["RUNNING", "CANCELLED", "FAILED"],
  RUNNING: ["COMPLETED", "PARTIAL", "FAILED", "CANCELLED"],
  COMPLETED: [],
  PARTIAL: [],
  FAILED: [],
  SKIPPED: [],
  CANCELLED: [],
};

export function canTransitionStage(from: StageStatus, to: StageStatus): boolean {
  return STAGE_TRANSITIONS[from].includes(to);
}

export class InvalidStageTransitionError extends Error {
  constructor(from: StageStatus, to: StageStatus) {
    super(`Invalid stage state transition: ${from} -> ${to}`);
    this.name = "InvalidStageTransitionError";
  }
}

export function assertStageTransition(from: StageStatus, to: StageStatus): void {
  if (!canTransitionStage(from, to)) throw new InvalidStageTransitionError(from, to);
}

export const EXECUTION_STATUSES = [
  "QUEUED", "PREPARING", "RUNNING", "PARSING", "NORMALIZING",
  "COMPLETED", "FAILED", "TIMED_OUT", "CANCELLING", "CANCELLED",
] as const;
export type ExecutionStatus = (typeof EXECUTION_STATUSES)[number];

export const EXECUTION_TRANSITIONS: Readonly<Record<ExecutionStatus, readonly ExecutionStatus[]>> = {
  QUEUED: ["PREPARING", "CANCELLING", "CANCELLED", "FAILED"],
  PREPARING: ["RUNNING", "CANCELLING", "CANCELLED", "FAILED", "TIMED_OUT"],
  RUNNING: ["PARSING", "CANCELLING", "CANCELLED", "FAILED", "TIMED_OUT"],
  PARSING: ["NORMALIZING", "FAILED", "TIMED_OUT"],
  NORMALIZING: ["COMPLETED", "FAILED"],
  COMPLETED: [],
  FAILED: [],
  TIMED_OUT: [],
  CANCELLING: ["CANCELLED", "FAILED"],
  CANCELLED: [],
};

export function canTransitionExecution(from: ExecutionStatus, to: ExecutionStatus): boolean {
  return EXECUTION_TRANSITIONS[from].includes(to);
}

export class InvalidExecutionTransitionError extends Error {
  constructor(from: ExecutionStatus, to: ExecutionStatus) {
    super(`Invalid tool-execution state transition: ${from} -> ${to}`);
    this.name = "InvalidExecutionTransitionError";
  }
}

export function assertExecutionTransition(from: ExecutionStatus, to: ExecutionStatus): void {
  if (!canTransitionExecution(from, to)) throw new InvalidExecutionTransitionError(from, to);
}

/** Failure strategies a stage may declare (Prompt 4 §8). */
export const FAILURE_STRATEGIES = [
  "FAIL_SCAN", "FAIL_STAGE_CONTINUE", "SKIP_DEPENDENTS", "CONTINUE_WITH_PARTIAL_DATA",
] as const;
export type FailureStrategy = (typeof FAILURE_STRATEGIES)[number];

/** What a stage failure means for its dependents, given its strategy. */
export function dependentOutcomeOnFailure(strategy: FailureStrategy): "SKIP" | "READY" | "FAIL_SCAN" {
  switch (strategy) {
    case "FAIL_SCAN": return "FAIL_SCAN";
    case "SKIP_DEPENDENTS": return "SKIP";
    case "FAIL_STAGE_CONTINUE":
    case "CONTINUE_WITH_PARTIAL_DATA": return "READY";
  }
}
