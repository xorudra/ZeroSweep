import { createHash } from "node:crypto";

/**
 * Notification routing core (Prompt 22 §65–§72): provider-neutral
 * decisions — fingerprinting, deduplication, grouping, throttling,
 * quiet hours and escalation. Delivery itself is performed by the
 * API service through configured providers only; an unconfigured
 * provider is recorded-not-delivered, never silently "sent".
 */

export const NOTIFICATION_CHANNELS = ["IN_APP", "EMAIL", "SLACK", "TEAMS", "WEBHOOK"] as const;
export type NotificationChannel = (typeof NOTIFICATION_CHANNELS)[number];

export interface NotificationEventView {
  type: string;
  workspaceId: string;
  findingId?: string;
  assetKey?: string;
  cve?: string;
  rootCauseKey?: string;
  severity?: string;
  priority?: string;
  /** Hash of the change content — identical content = same alert. */
  contentHash: string;
}

/** §68: stable fingerprint of an alert's identity + content. The same
 *  unchanged finding re-observed by a repeat scan produces the SAME
 *  fingerprint and is deduplicated inside the window (§116). */
export function alertFingerprint(event: NotificationEventView): string {
  return createHash("sha256")
    .update(["alert", event.type, event.findingId ?? "", event.assetKey ?? "", event.cve ?? "", event.contentHash].join(":"))
    .digest("hex");
}

/** §69: related alerts group by CVE, asset, campaign/schedule or
 *  root cause — in that precedence. */
export function alertGroupKey(event: NotificationEventView & { scheduleId?: string }): string {
  if (event.rootCauseKey) return `root:${event.rootCauseKey}`;
  if (event.cve) return `cve:${event.cve}`;
  if (event.scheduleId) return `schedule:${event.scheduleId}`;
  if (event.assetKey) return `asset:${event.assetKey}`;
  return `type:${event.type}`;
}

export interface NotificationPolicyView {
  eventTypes: string[];
  minSeverity?: string;
  minPriority?: string;
  riskThreshold?: number;
  channels: NotificationChannel[];
  dedupWindowMinutes: number;
  quietHours?: { startTime: string; endTime: string; timezone: string } | null;
  emergencySeverities?: string[];
  throttlePerHour?: number;
}

const SEVERITY_ORDER = ["INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
const PRIORITY_ORDER = ["P4", "P3", "P2", "P1", "P0"];

export function policyAdmitsEvent(
  policy: NotificationPolicyView,
  event: NotificationEventView & { riskScore?: number },
): { admitted: boolean; reason?: string } {
  if (!policy.eventTypes.includes(event.type)) return { admitted: false, reason: `event type ${event.type} not in policy` };
  if (policy.minSeverity && event.severity) {
    if (SEVERITY_ORDER.indexOf(event.severity) < SEVERITY_ORDER.indexOf(policy.minSeverity)) {
      return { admitted: false, reason: `severity ${event.severity} below policy minimum ${policy.minSeverity}` };
    }
  }
  if (policy.minPriority && event.priority) {
    if (PRIORITY_ORDER.indexOf(event.priority) < PRIORITY_ORDER.indexOf(policy.minPriority)) {
      return { admitted: false, reason: `priority ${event.priority} below policy minimum ${policy.minPriority}` };
    }
  }
  if (policy.riskThreshold !== undefined && event.riskScore !== undefined && event.riskScore < policy.riskThreshold) {
    return { admitted: false, reason: `risk score ${event.riskScore} below policy threshold ${policy.riskThreshold}` };
  }
  return { admitted: true };
}

/** §72: quiet hours in the policy's own timezone; explicitly
 *  configured emergency severities bypass them. */
export function isQuietHours(policy: NotificationPolicyView, event: NotificationEventView, now: Date): boolean {
  const qh = policy.quietHours;
  if (!qh) return false;
  if (event.severity && (policy.emergencySeverities ?? []).includes(event.severity)) return false;
  const fmt = new Intl.DateTimeFormat("en-US", { timeZone: qh.timezone, hour: "numeric", minute: "numeric", hour12: false });
  const parts = fmt.formatToParts(now);
  const get = (t: string) => Number(parts.find((p) => p.type === t)?.value ?? 0);
  const minutes = (get("hour") % 24) * 60 + get("minute");
  const [sh, sm] = qh.startTime.split(":").map(Number);
  const [eh, em] = qh.endTime.split(":").map(Number);
  const start = (sh ?? 0) * 60 + (sm ?? 0);
  const end = (eh ?? 0) * 60 + (em ?? 0);
  if (start === end) return false;
  if (start < end) return minutes >= start && minutes < end;
  return minutes >= start || minutes < end;
}

/** §70: sliding-window throttle over prior delivery timestamps. */
export function checkThrottle(input: {
  priorTimestamps: Date[];
  now: Date;
  limitPerHour: number;
}): { allowed: boolean; reason?: string } {
  const hourAgo = input.now.getTime() - 3600_000;
  const recent = input.priorTimestamps.filter((t) => t.getTime() > hourAgo).length;
  if (recent >= input.limitPerHour) {
    return { allowed: false, reason: `throttle: ${recent}/${input.limitPerHour} notifications in the last hour (§70)` };
  }
  return { allowed: true };
}

/** §71: escalation when a P0/P1 finding stays unresolved past the
 *  configured duration. */
export function escalationDue(input: {
  priority: string;
  unresolvedSince: Date;
  now: Date;
  escalateAfterMinutes: number;
  priorities: string[];
}): boolean {
  if (!input.priorities.includes(input.priority)) return false;
  return input.now.getTime() - input.unresolvedSince.getTime() >= input.escalateAfterMinutes * 60_000;
}
