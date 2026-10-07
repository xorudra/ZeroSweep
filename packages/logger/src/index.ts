/**
 * Structured JSON logger. NEVER log passwords, tokens, API keys, cookies or
 * authorization headers — redact() is applied to every metadata object.
 */
export type LogLevel = "debug" | "info" | "warn" | "error";

export interface LogContext {
  service?: string;
  requestId?: string;
  workspaceId?: string;
  scanId?: string;
  toolExecutionId?: string;
  [key: string]: unknown;
}

const SENSITIVE_KEY = /(password|passwd|secret|token|api[-_]?key|authorization|cookie|credential)/i;
export const REDACTED = "[REDACTED]";

export function redact<T>(value: T, depth = 0): T {
  if (depth > 6 || value === null || typeof value !== "object") return value;
  if (Array.isArray(value)) return value.map((v) => redact(v, depth + 1)) as T;
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    out[k] = SENSITIVE_KEY.test(k) ? REDACTED : redact(v, depth + 1);
  }
  return out as T;
}

export class Logger {
  constructor(private readonly base: LogContext = {}) {}
  child(ctx: LogContext): Logger {
    return new Logger({ ...this.base, ...ctx });
  }
  private emit(level: LogLevel, message: string, meta?: Record<string, unknown>): void {
    const entry = {
      timestamp: new Date().toISOString(),
      level,
      ...this.base,
      message,
      ...(meta ? redact(meta) : {}),
    };
    const line = JSON.stringify(entry);
    if (level === "error") process.stderr.write(line + "\n");
    else process.stdout.write(line + "\n");
  }
  debug(m: string, meta?: Record<string, unknown>): void { this.emit("debug", m, meta); }
  info(m: string, meta?: Record<string, unknown>): void { this.emit("info", m, meta); }
  warn(m: string, meta?: Record<string, unknown>): void { this.emit("warn", m, meta); }
  error(m: string, meta?: Record<string, unknown>): void { this.emit("error", m, meta); }
}

export function createLogger(service: string): Logger {
  return new Logger({ service });
}
