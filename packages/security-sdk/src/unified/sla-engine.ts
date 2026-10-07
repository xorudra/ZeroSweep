/**
 * SLA engine V2 (Prompt 20 §28–§30).
 *
 * A policy maps severity/priority (+ environment, asset-criticality and
 * finding-type modifiers) to THREE deadlines: triage, remediation and
 * retest. States are ON_TRACK / DUE_SOON / OVERDUE / PAUSED /
 * NOT_APPLICABLE (§29) — PAUSED requires an auditable reason (§30) and
 * closed findings are NOT_APPLICABLE, never "exempt by silence".
 * Everything is computed from stored timestamps; nothing is invented
 * when a policy has no matching rule (the deadline is honestly absent).
 */

export type UnifiedSlaState = "ON_TRACK" | "DUE_SOON" | "OVERDUE" | "PAUSED" | "NOT_APPLICABLE";

export interface SlaDeadlineRules {
  byPriority?: Partial<Record<string, number>>; // hours
  bySeverity?: Partial<Record<string, number>>; // hours
}

export interface VmSlaPolicyRules {
  triageHours?: SlaDeadlineRules;
  remediationHours?: SlaDeadlineRules;
  retestHours?: SlaDeadlineRules;
  /** Multipliers applied to remediation hours (§28 inputs). */
  environmentMultiplier?: Partial<Record<string, number>>; // e.g. PRODUCTION 1, LAB 2
  criticalityMultiplier?: Partial<Record<string, number>>; // e.g. CRITICAL 0.5
  typeMultiplier?: Partial<Record<string, number>>; // by category
}

export interface VmSlaPolicyView {
  id: string;
  name: string;
  rules: VmSlaPolicyRules;
}

export const DEFAULT_VM_SLA_POLICY: VmSlaPolicyView = {
  id: "default-v2",
  name: "Default unified SLA policy",
  rules: {
    triageHours: { bySeverity: { CRITICAL: 24, HIGH: 72, MEDIUM: 168, LOW: 336, INFORMATIONAL: 720 } },
    remediationHours: {
      byPriority: { P0: 48, P1: 168, P2: 720, P3: 2160, P4: 4320 },
      bySeverity: { CRITICAL: 48, HIGH: 168, MEDIUM: 720, LOW: 2160, INFORMATIONAL: 4320 },
    },
    retestHours: { bySeverity: { CRITICAL: 72, HIGH: 168, MEDIUM: 336, LOW: 720, INFORMATIONAL: 1440 } },
    environmentMultiplier: { PRODUCTION: 1, STAGING: 1.5, DEVELOPMENT: 2, LAB: 3 },
    criticalityMultiplier: { CRITICAL: 0.5, HIGH: 0.75, MEDIUM: 1, LOW: 1.5, UNSPECIFIED: 1 },
  },
};

function baseHours(rules: SlaDeadlineRules | undefined, input: { priority?: string | null; severity: string }): number | undefined {
  if (!rules) return undefined;
  if (input.priority && rules.byPriority?.[input.priority] !== undefined) return rules.byPriority[input.priority];
  return rules.bySeverity?.[input.severity];
}

export interface SlaDeadlines {
  triageDueAt?: Date;
  remediationDueAt?: Date;
  retestDueAt?: Date;
  /** The remediation hours actually applied (after §28 modifiers). */
  appliedRemediationHours?: number;
  notes: string[];
}

export function computeSlaDeadlines(
  policy: VmSlaPolicyView,
  input: {
    severity: string;
    priority?: string | null;
    createdAt: Date;
    environment?: string | null;
    assetCriticality?: string | null;
    category?: string | null;
    remediatedAt?: Date | null;
  },
): SlaDeadlines {
  const notes: string[] = [];
  const out: SlaDeadlines = { notes };
  const triage = baseHours(policy.rules.triageHours, input);
  if (triage !== undefined) out.triageDueAt = new Date(input.createdAt.getTime() + triage * 3600_000);

  let rem = baseHours(policy.rules.remediationHours, input);
  if (rem !== undefined) {
    const envMult = input.environment ? policy.rules.environmentMultiplier?.[input.environment] : undefined;
    if (envMult !== undefined) { rem *= envMult; notes.push(`remediation window × ${envMult} for environment ${input.environment} (§28)`); }
    const critMult = input.assetCriticality ? policy.rules.criticalityMultiplier?.[input.assetCriticality] : undefined;
    if (critMult !== undefined) { rem *= critMult; notes.push(`remediation window × ${critMult} for asset criticality ${input.assetCriticality} (§28)`); }
    const typeMult = input.category ? policy.rules.typeMultiplier?.[input.category] : undefined;
    if (typeMult !== undefined) { rem *= typeMult; notes.push(`remediation window × ${typeMult} for category ${input.category} (§28)`); }
    out.appliedRemediationHours = rem;
    out.remediationDueAt = new Date(input.createdAt.getTime() + rem * 3600_000);
  } else {
    notes.push("policy has no remediation rule for this severity/priority — no deadline is claimed (§28)");
  }

  const retest = baseHours(policy.rules.retestHours, input);
  if (retest !== undefined && input.remediatedAt) {
    out.retestDueAt = new Date(input.remediatedAt.getTime() + retest * 3600_000);
  }
  return out;
}

const CLOSED = new Set(["RESOLVED", "FALSE_POSITIVE", "DUPLICATE"]);

/** §29 state for ONE deadline. Pause (§30) needs a recorded reason. */
export function slaStateFor(input: {
  dueAt?: Date | string | null;
  lifecycleStatus: string;
  createdAt: Date | string;
  pausedAt?: Date | string | null;
  pauseReason?: string | null;
}, now: Date = new Date()): UnifiedSlaState {
  if (CLOSED.has(input.lifecycleStatus)) return "NOT_APPLICABLE";
  if (input.pausedAt && input.pauseReason) return "PAUSED";
  const due = input.dueAt ? new Date(input.dueAt) : undefined;
  if (!due || Number.isNaN(due.getTime())) return "NOT_APPLICABLE";
  if (now > due) return "OVERDUE";
  const created = new Date(input.createdAt);
  const windowMs = due.getTime() - created.getTime();
  const remaining = due.getTime() - now.getTime();
  if (windowMs > 0 && remaining <= windowMs * 0.25) return "DUE_SOON";
  return "ON_TRACK";
}

/** §30: the auditable timer events a finding accumulates. */
export type SlaTimerEvent = "CREATED" | "TRIAGED" | "ASSIGNED" | "REMEDIATED" | "RETEST_REQUESTED" | "RESOLVED" | "PAUSED" | "RESUMED";

export interface SlaTimer {
  createdAt: Date;
  triagedAt?: Date;
  assignedAt?: Date;
  remediatedAt?: Date;
  retestRequestedAt?: Date;
  resolvedAt?: Date;
  pauses: { pausedAt: Date; reason: string; resumedAt?: Date }[];
}
