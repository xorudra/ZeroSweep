import { randomUUID } from "node:crypto";
import { escapeHtmlText } from "./sanitize";
import { EVENT_SCHEMA_VERSION, type SecurityEventEnvelope, type SiemEventType } from "./types";

/**
 * Security event bus, SIEM mapping and delivery reliability
 * (Prompt 24 §61–§67, §72, §75–§80, §96, §97, §131).
 *
 * Producers publish canonical envelopes; integrations subscribe via
 * the transactional outbox — scanners never call integrations
 * directly (§75). Delivery is at-least-once with bounded retries and
 * dead-lettering (§72); consumers dedupe on the stable event ID
 * (§67/§131), so the pair is logically exactly-once.
 */

export function createEventEnvelope<T extends Record<string, unknown>>(input: {
  eventType: string;
  workspaceId: string;
  resourceType: string;
  resourceId: string;
  payload: T;
  eventId?: string;
  now?: Date;
}): SecurityEventEnvelope<T> {
  return {
    eventId: input.eventId ?? randomUUID(),
    eventType: input.eventType,
    workspaceId: input.workspaceId,
    timestamp: (input.now ?? new Date()).toISOString(),
    resourceType: input.resourceType,
    resourceId: input.resourceId,
    schemaVersion: EVENT_SCHEMA_VERSION,
    payload: input.payload,
  };
}

/** §64: the SIEM event shape. References and scores only — no
 *  evidence, no secrets, ever (§64). */
export interface SiemEvent {
  eventId: string;
  timestamp: string;
  workspaceId: string;
  eventType: SiemEventType | string;
  severity: string;
  findingId?: string;
  assetReference?: string;
  riskScore?: number;
  cve?: string;
  cwe?: string;
  status: string;
}

export function toSiemEvent(input: {
  eventId: string; timestamp: string; workspaceId: string; eventType: string;
  severity: string; status: string;
  findingId?: string; assetReference?: string; riskScore?: number; cve?: string; cwe?: string;
}): SiemEvent {
  return {
    eventId: input.eventId,
    timestamp: input.timestamp,
    workspaceId: input.workspaceId,
    eventType: input.eventType,
    severity: input.severity,
    status: input.status,
    ...(input.findingId ? { findingId: input.findingId } : {}),
    ...(input.assetReference ? { assetReference: input.assetReference } : {}),
    ...(input.riskScore != null ? { riskScore: input.riskScore } : {}),
    ...(input.cve ? { cve: input.cve } : {}),
    ...(input.cwe ? { cwe: input.cwe } : {}),
  };
}

const CEF_SEVERITY: Record<string, number> = { INFORMATIONAL: 0, LOW: 3, MEDIUM: 5, HIGH: 8, CRITICAL: 10 };

function cefEscape(value: string): string {
  return value.replace(/\\/g, "\\\\").replace(/\|/g, "\\|").replace(/=/g, "\\=").replace(/[\r\n]/g, " ");
}

/** §63: CEF rendering of a SIEM event. */
export function formatCef(event: SiemEvent): string {
  const extensions = [
    `externalId=${cefEscape(event.eventId)}`,
    event.findingId ? `cs1=${cefEscape(event.findingId)} cs1Label=findingId` : "",
    event.cve ? `cs2=${cefEscape(event.cve)} cs2Label=cve` : "",
    event.riskScore != null ? `cn1=${event.riskScore} cn1Label=riskScore` : "",
    `outcome=${cefEscape(event.status)}`,
  ].filter(Boolean).join(" ");
  return `CEF:0|DSRclone|DSRclone|1.0|${cefEscape(event.eventType)}|${cefEscape(event.eventType)}|${CEF_SEVERITY[event.severity] ?? 5}|${extensions}`;
}

/** §63: LEEF rendering of a SIEM event. */
export function formatLeef(event: SiemEvent): string {
  const fields = [
    `eventId=${cefEscape(event.eventId)}`,
    `severity=${cefEscape(event.severity)}`,
    `status=${cefEscape(event.status)}`,
    event.findingId ? `findingId=${cefEscape(event.findingId)}` : "",
    event.cve ? `cve=${cefEscape(event.cve)}` : "",
  ].filter(Boolean).join("\t");
  return `LEEF:2.0|DSRclone|DSRclone|1.0|${cefEscape(event.eventType)}|^|${fields}`;
}

/* ------------------------- delivery reliability ------------------------ */

/** §66/§72: bounded delivery attempts — never infinite. */
export const MAX_DELIVERY_ATTEMPTS = 5;

/** Exponential backoff schedule for attempts 1..n (§66/§72). */
export function nextRetryDelayMs(failedAttempt: number): number {
  const schedule = [30_000, 120_000, 600_000, 1_800_000, 7_200_000];
  return schedule[Math.min(Math.max(failedAttempt - 1, 0), schedule.length - 1)]!;
}

export function shouldDeadLetter(attempts: number): boolean {
  return attempts >= MAX_DELIVERY_ATTEMPTS;
}

/** §97: honor provider Retry-After (seconds or HTTP-date), capped so
 *  a hostile/buggy provider cannot park the queue forever. */
export function retryAfterDelayMs(headers: Record<string, string> | undefined, nowMs: number): number | null {
  if (!headers) return null;
  const raw = headers["retry-after"] ?? headers["Retry-After"];
  if (!raw) return null;
  const seconds = Number(raw);
  let delay: number;
  if (Number.isFinite(seconds)) delay = seconds * 1000;
  else {
    const at = Date.parse(raw);
    if (!Number.isFinite(at)) return null;
    delay = at - nowMs;
  }
  if (delay < 0) return 0;
  return Math.min(delay, 3_600_000);
}

/**
 * §96: circuit breaker for failing external services. After
 * `failureThreshold` consecutive failures the breaker OPENs and calls
 * fail fast (the integration is marked DEGRADED, §104); after the
 * cooldown a single HALF_OPEN probe decides.
 */
export class CircuitBreaker {
  private failures = 0;
  private openedAtMs: number | null = null;
  constructor(
    private readonly failureThreshold = 5,
    private readonly cooldownMs = 60_000,
  ) {}

  state(nowMs: number): "CLOSED" | "OPEN" | "HALF_OPEN" {
    if (this.openedAtMs === null) return "CLOSED";
    return nowMs - this.openedAtMs >= this.cooldownMs ? "HALF_OPEN" : "OPEN";
  }

  canExecute(nowMs: number): boolean {
    return this.state(nowMs) !== "OPEN";
  }

  recordSuccess(): void {
    this.failures = 0;
    this.openedAtMs = null;
  }

  recordFailure(nowMs: number): void {
    this.failures += 1;
    if (this.failures >= this.failureThreshold) this.openedAtMs = nowMs;
  }

  get consecutiveFailures(): number {
    return this.failures;
  }
}

/** Escape helper re-exported for artifact builders (§114). */
export { escapeHtmlText };
