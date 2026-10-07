/**
 * Tool exit-behaviour classification (Prompt 5 §38). Neither "non-zero is
 * always fatal" nor "zero means results" is true for recon tools: several
 * exit non-zero after printing partial results, and several exit zero with
 * nothing but warnings. Each adapter declares its acceptable exit codes and
 * whether empty output is a legitimate success; classification combines the
 * exit code with whether parseable output exists.
 */

export type ToolOutcome = "SUCCESS" | "PARTIAL" | "FAILED" | "TIMED_OUT" | "CANCELLED";

export interface ExitClassification {
  outcome: ToolOutcome;
  reason: string;
}

export function classifyToolOutcome(input: {
  exitCode: number | null;
  acceptableExitCodes: readonly number[];
  hasOutput: boolean;
  /** True when empty stdout is a valid "found nothing" result for this tool. */
  emptyOutputIsSuccess: boolean;
  timedOut?: boolean;
  cancelled?: boolean;
}): ExitClassification {
  if (input.cancelled) return { outcome: "CANCELLED", reason: "execution was cancelled" };
  if (input.timedOut) return { outcome: "TIMED_OUT", reason: "execution exceeded its timeout" };
  const acceptable = input.exitCode !== null && input.acceptableExitCodes.includes(input.exitCode);
  if (acceptable && (input.hasOutput || input.emptyOutputIsSuccess)) {
    return { outcome: "SUCCESS", reason: `exit ${input.exitCode} with ${input.hasOutput ? "output" : "legitimately empty output"}` };
  }
  if (input.hasOutput) {
    // Output exists despite an unhappy exit (or a null/unknown code): the
    // parser decides record-by-record; the run is PARTIAL, never a crash.
    return { outcome: "PARTIAL", reason: `exit ${input.exitCode ?? "unknown"} but output was produced` };
  }
  return { outcome: "FAILED", reason: `exit ${input.exitCode ?? "unknown"} with no output` };
}
