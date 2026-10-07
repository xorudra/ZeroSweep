import { ArtifactLimitError, ExecutionTimeoutError } from "../adapter/adapter.errors";
import { DEFAULT_LIMITS, type ExecutionLimits } from "./execution.types";

/**
 * Limit enforcement (Prompt 3 §30–§33). Adapters and assessment profiles may
 * ask for LESS than the administrator maximums, never more: every request is
 * clamped to (or rejected above) the admin ceiling.
 */
export function clampTimeout(requestedSeconds: number, adapterMaxSeconds: number, admin: ExecutionLimits = DEFAULT_LIMITS): number {
  if (!(requestedSeconds > 0)) throw new ExecutionTimeoutError("Timeout must be positive");
  const ceiling = Math.min(adapterMaxSeconds, admin.maxTimeoutSeconds);
  if (requestedSeconds > ceiling) throw new ExecutionTimeoutError(`Requested timeout ${requestedSeconds}s exceeds maximum ${ceiling}s`);
  return requestedSeconds;
}

export interface RateLimitModel {
  requestsPerSecond: number;
  requestsPerMinute: number;
  maxConcurrency: number;
}

export function clampRateLimits(requested: Partial<RateLimitModel>, admin: ExecutionLimits = DEFAULT_LIMITS): RateLimitModel {
  return {
    requestsPerSecond: Math.max(0, Math.min(requested.requestsPerSecond ?? 1, Math.ceil(admin.requestsPerMinute / 60))),
    requestsPerMinute: Math.max(0, Math.min(requested.requestsPerMinute ?? admin.requestsPerMinute, admin.requestsPerMinute)),
    maxConcurrency: Math.max(1, Math.min(requested.maxConcurrency ?? admin.maxConcurrency, admin.maxConcurrency)),
  };
}

export interface OutputAccounting {
  stdoutBytes: number;
  stderrBytes: number;
  artifactSizes: number[];
}

/** Throws ArtifactLimitError the moment any output ceiling is exceeded, so a
 *  broken or malicious tool cannot fill disk or the database. */
export function enforceOutputLimits(acc: OutputAccounting, limits: ExecutionLimits = DEFAULT_LIMITS): void {
  if (acc.stdoutBytes > limits.maxStdoutBytes) throw new ArtifactLimitError(`stdout exceeds ${limits.maxStdoutBytes} bytes`);
  if (acc.stderrBytes > limits.maxStderrBytes) throw new ArtifactLimitError(`stderr exceeds ${limits.maxStderrBytes} bytes`);
  if (acc.artifactSizes.length > limits.maxArtifacts) throw new ArtifactLimitError(`artifact count exceeds ${limits.maxArtifacts}`);
  for (const s of acc.artifactSizes) {
    if (s > limits.maxArtifactBytes) throw new ArtifactLimitError(`artifact exceeds ${limits.maxArtifactBytes} bytes`);
  }
  const total = acc.artifactSizes.reduce((a, b) => a + b, 0);
  if (total > limits.maxArtifactBytes * limits.maxArtifacts) throw new ArtifactLimitError("total execution output exceeds limit");
}

export function truncateSafely(text: string, maxBytes: number): { text: string; truncated: boolean } {
  const buf = Buffer.from(text, "utf8");
  if (buf.length <= maxBytes) return { text, truncated: false };
  return { text: buf.subarray(0, maxBytes).toString("utf8"), truncated: true };
}
