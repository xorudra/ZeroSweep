import type { SlaState } from "./types";

/**
 * Remediation SLA resolution + clock (Prompt 31 §21–§31). Policies are
 * configuration, never global constants (§22): the resolver scores the
 * workspace's configured policies against the case inputs and picks the
 * most specific match; the P11 flat priority-hours map is the fallback
 * duration source. The snapshot stores policy version + inputs so a due
 * date stays explainable after the policy changes (§24).
 */
export interface RemediationSlaPolicyView {
  id: string;
  name: string;
  version: number;
  isDefault: boolean;
  active: boolean;
  /** Flat P0..P4 / severity hours (P11 rules map). */
  rules: Record<string, number>;
  conditions?: {
    severities?: string[];
    priorities?: string[];
    kevOnly?: boolean;
    internetExposed?: boolean;
    criticalities?: string[];
    categories?: string[];
    targetHours?: number;
    verificationRequired?: boolean;
    requiredCleanObservations?: number;
    dualApprovalForHighRisk?: boolean;
  } | null;
  warningThresholds?: { warningPct?: number; atRiskPct?: number } | null;
  escalation?: { escalateTo?: string[]; managementRoute?: string } | null;
  verificationRequired: boolean;
  requiredCleanObservations: number;
}

export interface SlaResolutionInputs {
  priority?: string | null;
  severity: string;
  kevListed: boolean;
  internetExposed: boolean;
  assetCriticality?: string | null;
  category?: string | null;
}

export interface SlaResolution {
  policyId: string | null;
  policyVersion: number | null;
  targetHours: number;
  verificationRequired: boolean;
  requiredCleanObservations: number;
  dualApprovalForHighRisk: boolean;
  warningPct: number;
  atRiskPct: number;
  specificity: number;
  /** The exact inputs used — persisted on the snapshot (§24). */
  inputs: SlaResolutionInputs;
}

function conditionSpecificity(policy: RemediationSlaPolicyView, inputs: SlaResolutionInputs): number | null {
  const c = policy.conditions;
  if (!c) return policy.isDefault ? 0 : null;
  let score = 0;
  if (c.severities?.length) {
    if (!c.severities.includes(inputs.severity)) return null;
    score += 2;
  }
  if (c.priorities?.length) {
    if (!inputs.priority || !c.priorities.includes(inputs.priority)) return null;
    score += 2;
  }
  if (c.kevOnly) {
    if (!inputs.kevListed) return null;
    score += 3;
  }
  if (c.internetExposed !== undefined) {
    if (c.internetExposed !== inputs.internetExposed) return null;
    score += 2;
  }
  if (c.criticalities?.length) {
    if (!inputs.assetCriticality || !c.criticalities.includes(inputs.assetCriticality)) return null;
    score += 2;
  }
  if (c.categories?.length) {
    if (!inputs.category || !c.categories.includes(inputs.category)) return null;
    score += 1;
  }
  return score;
}

function durationHours(policy: RemediationSlaPolicyView, inputs: SlaResolutionInputs): number | null {
  if (policy.conditions?.targetHours && policy.conditions.targetHours > 0) return policy.conditions.targetHours;
  if (inputs.priority && policy.rules[inputs.priority]) return policy.rules[inputs.priority];
  if (policy.rules[inputs.severity]) return policy.rules[inputs.severity];
  return null;
}

/** Resolve the applicable policy (§23). Returns null when no configured
 *  policy yields a duration — the caller must surface that, never
 *  silently invent a due date. */
export function resolveRemediationSla(
  policies: RemediationSlaPolicyView[],
  inputs: SlaResolutionInputs,
): SlaResolution | null {
  let best: { policy: RemediationSlaPolicyView; score: number; hours: number } | null = null;
  for (const policy of policies) {
    if (!policy.active) continue;
    const score = conditionSpecificity(policy, inputs);
    if (score === null) continue;
    const hours = durationHours(policy, inputs);
    if (hours === null || hours <= 0) continue;
    if (!best || score > best.score || (score === best.score && policy.isDefault && !best.policy.isDefault)) {
      best = { policy, score, hours };
    }
  }
  if (!best) return null;
  const { policy } = best;
  return {
    policyId: policy.id,
    policyVersion: policy.version,
    targetHours: best.hours,
    verificationRequired: policy.conditions?.verificationRequired ?? policy.verificationRequired,
    requiredCleanObservations: policy.conditions?.requiredCleanObservations ?? policy.requiredCleanObservations ?? 1,
    dualApprovalForHighRisk: policy.conditions?.dualApprovalForHighRisk ?? false,
    warningPct: policy.warningThresholds?.warningPct ?? 0.5,
    atRiskPct: policy.warningThresholds?.atRiskPct ?? 0.8,
    specificity: best.score,
    inputs,
  };
}

export interface SlaSnapshotView {
  startedAt: Date;
  dueAt: Date;
  pausedDurationMs: number;
  pausedAt: Date | null;
  completedAt: Date | null;
  state: SlaState;
  warningPct: number;
  atRiskPct: number;
}

/**
 * SLA clock + state derivation (§26/§27). Paused time never counts
 * against the target: the effective deadline is dueAt + pausedDuration
 * (+ the in-flight pause, while paused). States derive purely from
 * stored timestamps — tests drive this with a fake clock (§136).
 */
export function deriveSlaState(snapshot: SlaSnapshotView, now: Date): { state: SlaState; elapsedPct: number; effectiveDueAt: Date } {
  const targetMs = snapshot.dueAt.getTime() - snapshot.startedAt.getTime();
  let pausedMs = snapshot.pausedDurationMs;
  if (snapshot.pausedAt) pausedMs += Math.max(0, now.getTime() - snapshot.pausedAt.getTime());
  const effectiveDueAt = new Date(snapshot.dueAt.getTime() + snapshot.pausedDurationMs);
  if (snapshot.completedAt) return { state: "COMPLETED", elapsedPct: 1, effectiveDueAt };
  if (snapshot.pausedAt) return { state: "PAUSED", elapsedPct: 0, effectiveDueAt };
  const end = snapshot.completedAt ?? now;
  const elapsedMs = Math.max(0, end.getTime() - snapshot.startedAt.getTime() - pausedMs);
  const elapsedPct = targetMs > 0 ? elapsedMs / targetMs : 1;
  if (now.getTime() > effectiveDueAt.getTime()) return { state: "BREACHED", elapsedPct, effectiveDueAt };
  if (elapsedPct >= snapshot.atRiskPct) return { state: "AT_RISK", elapsedPct, effectiveDueAt };
  if (elapsedPct >= snapshot.warningPct) return { state: "WARNING", elapsedPct, effectiveDueAt };
  return { state: "ON_TRACK", elapsedPct, effectiveDueAt };
}

/**
 * SLA recalculation guard (§25): a material risk change may PROPOSE a
 * new due date, but an existing due date is never silently shortened —
 * shortening applies only when the governing policy explicitly allows
 * it; extension always applies.
 */
export function evaluateSlaRecalculation(input: {
  currentDueAt: Date;
  proposedDueAt: Date;
  allowShorten: boolean;
}): { applied: boolean; dueAt: Date; shortened: boolean; reason: string } {
  const shortened = input.proposedDueAt.getTime() < input.currentDueAt.getTime();
  if (!shortened) {
    return { applied: true, dueAt: input.proposedDueAt, shortened: false, reason: "extension (or unchanged) applies immediately" };
  }
  if (input.allowShorten) {
    return { applied: true, dueAt: input.proposedDueAt, shortened: true, reason: "policy explicitly allows shortening on material risk increase" };
  }
  return { applied: false, dueAt: input.currentDueAt, shortened: true, reason: "shortening blocked: policy does not allow silently shortening an existing due date (§25)" };
}
