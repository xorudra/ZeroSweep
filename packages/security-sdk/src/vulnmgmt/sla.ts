import type { RemediationPriority } from "./risk-v2";

/**
 * Remediation SLA (Prompt 11 §41–§43). Policies are CONFIGURABLE — rules
 * map priority (preferred) or severity to a resolution window in hours;
 * no organization's policy is hardcoded (§41). dueAt is computed from
 * the finding's creation/confirmation time (§42); status is one of
 * ON_TRACK / DUE_SOON / OVERDUE / EXEMPT (§43). Findings closed as
 * RESOLVED / FALSE_POSITIVE, and findings under an unexpired risk
 * acceptance, are EXEMPT from SLA pressure.
 */

export interface SlaPolicyRules {
  /** Hours per remediation priority (P0..P4), §40/§41. */
  byPriority?: Partial<Record<RemediationPriority, number>>;
  /** Hours per severity — used when a finding has no priority yet. */
  bySeverity?: Partial<Record<string, number>>;
}

export interface SlaPolicy {
  id: string;
  name: string;
  rules: SlaPolicyRules;
}

/** A reasonable STARTER policy an admin can edit — shipped as data, not
 *  as a hardcoded rule (§41): Critical 48h, High 7d, Medium 30d, Low 90d
 *  expressed on the priority scale. */
export const DEFAULT_SLA_POLICY: SlaPolicy = {
  id: "default",
  name: "Default SLA policy",
  rules: {
    byPriority: { P0: 24, P1: 48, P2: 168, P3: 720, P4: 2160 },
    bySeverity: { CRITICAL: 48, HIGH: 168, MEDIUM: 720, LOW: 2160, INFORMATIONAL: 2160 },
  },
};

export type SlaStatus = "ON_TRACK" | "DUE_SOON" | "OVERDUE" | "EXEMPT";

const DUE_SOON_FRACTION = 0.25; // last 25% of the window = due soon

export function slaWindowHours(policy: SlaPolicy, input: { priority?: string | null; severity: string }): number | undefined {
  if (input.priority && policy.rules.byPriority) {
    const h = policy.rules.byPriority[input.priority as RemediationPriority];
    if (h !== undefined) return h;
  }
  return policy.rules.bySeverity?.[input.severity];
}

/** §42: dueAt = anchor (creation, or confirmation when later provided) +
 *  the policy window. Undefined when the policy has no matching rule —
 *  the finding then honestly has no SLA deadline. */
export function computeDueAt(policy: SlaPolicy, input: { priority?: string | null; severity: string; createdAt: Date; confirmedAt?: Date | null }): Date | undefined {
  const hours = slaWindowHours(policy, input);
  if (hours === undefined) return undefined;
  const anchor = input.confirmedAt && input.confirmedAt > input.createdAt ? input.confirmedAt : input.createdAt;
  return new Date(anchor.getTime() + hours * 3600_000);
}

export function slaStatus(input: {
  dueAt?: Date | string | null;
  lifecycleStatus: string;
  createdAt: Date | string;
  policy?: SlaPolicy;
  priority?: string | null;
  severity: string;
}, now: Date = new Date()): SlaStatus {
  if (input.lifecycleStatus === "RESOLVED" || input.lifecycleStatus === "FALSE_POSITIVE" || input.lifecycleStatus === "ACCEPTED_RISK") return "EXEMPT";
  const due = input.dueAt ? (input.dueAt instanceof Date ? input.dueAt : new Date(input.dueAt)) : undefined;
  if (!due || Number.isNaN(due.getTime())) return "ON_TRACK"; // no deadline defined — not overdue, just untracked
  if (now > due) return "OVERDUE";
  const created = input.createdAt instanceof Date ? input.createdAt : new Date(input.createdAt);
  const windowMs = due.getTime() - created.getTime();
  const remaining = due.getTime() - now.getTime();
  if (windowMs > 0 && remaining <= windowMs * DUE_SOON_FRACTION) return "DUE_SOON";
  return "ON_TRACK";
}
