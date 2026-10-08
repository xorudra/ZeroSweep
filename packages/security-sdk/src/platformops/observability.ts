/**
 * Observability safety (Prompt 38 §96–§123, §223–§224): metric
 * cardinality discipline and log/trace redaction screening. The logger
 * package redacts log metadata; this module is the shared contract for
 * metric labels and span attributes, where a secret or a high-
 * cardinality identifier is a production incident, not a style issue.
 */

/** Labels that must never appear on a metric (§107): unbounded or
 *  identifying values explode cardinality and leak tenant structure. */
export const FORBIDDEN_METRIC_LABELS = new Set([
  "user_id", "userId", "asset_id", "assetId", "finding_id", "findingId",
  "target", "hostname", "host", "url", "path", "error", "error_message",
  "request_id", "requestId", "trace_id", "traceId", "email", "ip",
  "workspace_id", "workspaceId", "organization_id", "organizationId",
]);

export function metricLabelViolations(labels: Record<string, string>): string[] {
  return Object.keys(labels).filter((k) => FORBIDDEN_METRIC_LABELS.has(k));
}

/** §98: every platform metric carries the dsrclone_ prefix. */
export function metricNameValid(name: string): boolean {
  return /^dsrclone_[a-z0-9_]+$/.test(name);
}

const SENSITIVE_ATTRIBUTE = /(authorization|cookie|password|passwd|secret|token|api[-_]?key|private[-_]?key|credential|session)/i;

/**
 * Span attribute screening (§116/§224): returns a COPY with sensitive
 * keys removed entirely (not masked — a masked secret in a trace is
 * still a secret in a trace) and oversized values dropped. Raw payloads
 * and evidence never belong on spans.
 */
export function screenSpanAttributes(attrs: Record<string, unknown>): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(attrs)) {
    if (SENSITIVE_ATTRIBUTE.test(k)) continue;
    if (typeof v === "string" && v.length > 512) continue;
    if (v !== null && typeof v === "object") continue;
    out[k] = v;
  }
  return out;
}

/**
 * W3C trace context (§113–§115): traceparent parsing/formatting so
 * context propagates web → API → queue → worker without any external
 * tracing dependency. Invalid headers are ignored, never trusted.
 */
export interface TraceContext { traceId: string; parentSpanId: string; sampled: boolean }

export function parseTraceparent(header: string | undefined): TraceContext | null {
  if (!header) return null;
  const m = /^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/.test(header.trim())
    ? header.trim().split("-")
    : null;
  if (!m) return null;
  const [, traceId, parentSpanId, flags] = m;
  if (traceId === "0".repeat(32) || parentSpanId === "0".repeat(16)) return null;
  return { traceId: traceId!, parentSpanId: parentSpanId!, sampled: (parseInt(flags!, 16) & 1) === 1 };
}

export function formatTraceparent(ctx: TraceContext): string {
  return `00-${ctx.traceId}-${ctx.parentSpanId}-${ctx.sampled ? "01" : "00"}`;
}
