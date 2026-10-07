/**
 * Idempotency + retry policy (Prompt 4 §15, §29). Every queue job carries a
 * deterministic idempotency key (scanId + stageId + executionAttempt) so a
 * duplicate delivery can never execute the same stage twice. Only transient
 * failures retry, with bounded exponential backoff; policy/scope/target
 * failures are terminal by design.
 */

export function idempotencyKey(scanId: string, stageId: string, attempt: number): string {
  return `${scanId}:${stageId}:${attempt}`;
}

export function stageJobId(scanId: string, stageId: string, attempt: number): string {
  return `stage-${idempotencyKey(scanId, stageId, attempt)}`;
}

export type ErrorCategory =
  | "TRANSIENT"      // Redis/network blips, temporary worker failure
  | "CONFIGURATION"  // missing config/credentials reference
  | "POLICY"         // policy engine denied execution
  | "TARGET_ERROR"   // invalid/unreachable target input
  | "SCOPE"          // scope violation
  | "TOOL_ERROR"     // adapter/tool failure
  | "TIMEOUT"        // execution exceeded its timeout
  | "PARSER";        // output could not be parsed (bounded retry)

export const RETRYABLE_CATEGORIES: ReadonlySet<ErrorCategory> = new Set(["TRANSIENT", "PARSER"]);

export interface RetryDecision {
  retry: boolean;
  nextAttempt: number;
  delayMs: number;
  reason: string;
}

export function classifyError(error: unknown): ErrorCategory {
  const name = error instanceof Error ? error.name : "";
  const message = error instanceof Error ? error.message : String(error);
  if (name === "PolicyDeniedError" || /policy/i.test(message)) return "POLICY";
  if (name === "ScopeViolationError" || /scope/i.test(message)) return "SCOPE";
  if (name === "ExecutionTimeoutError" || /timeout/i.test(message)) return "TIMEOUT";
  if (name === "ParserError") return "PARSER";
  if (name === "AdapterConfigurationError") return "CONFIGURATION";
  if (name === "UnsupportedTargetError") return "TARGET_ERROR";
  if (/ECONNREFUSED|ETIMEDOUT|redis|socket/i.test(message)) return "TRANSIENT";
  return "TOOL_ERROR";
}

export function retryDecision(category: ErrorCategory, attempt: number, maxAttempts = 3): RetryDecision {
  if (!RETRYABLE_CATEGORIES.has(category)) {
    return { retry: false, nextAttempt: attempt, delayMs: 0, reason: `${category} failures are not retried` };
  }
  if (attempt >= maxAttempts) {
    return { retry: false, nextAttempt: attempt, delayMs: 0, reason: `attempt budget exhausted (${maxAttempts})` };
  }
  const delayMs = Math.min(30_000, 1_000 * 2 ** (attempt - 1));
  return { retry: true, nextAttempt: attempt + 1, delayMs, reason: `${category} failure — retry with backoff` };
}
