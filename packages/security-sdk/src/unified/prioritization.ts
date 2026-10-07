import { basePriorityForScore, escalatePriority, type RemediationPriority } from "../vulnmgmt/risk-v2";

/**
 * RemediationPrioritizationService (Prompt 20 §24/§25).
 *
 * Priority is the ORDER WORK SHOULD HAPPEN — a business decision built
 * from risk + context. It is never a copy of severity (§11) and never
 * a copy of the risk score alone: verified status, public exposure,
 * KEV, EPSS, asset criticality, SLA pressure and fix availability all
 * move it, and every move is explained.
 *
 * §25 is explicit: a Verified KEV finding on an internet-facing
 * production asset gets STRONG prioritization — but not every KEV is
 * automatically P0 regardless of context.
 */

export interface PrioritizationInput {
  riskScore: number;
  severity: string;
  kevListed?: boolean;
  epssScore?: number;
  internetExposed?: boolean;
  assetCriticality?: string;
  verificationStatus?: string; // unified vocabulary: VERIFIED | LIKELY | UNVERIFIED | INCONCLUSIVE
  environment?: string;
  slaState?: string;
  remediationAvailable?: boolean;
}

export interface PrioritizationResult {
  priority: RemediationPriority;
  rationale: string[];
}

export function prioritize(input: PrioritizationInput): PrioritizationResult {
  const rationale: string[] = [];
  let priority = basePriorityForScore(input.riskScore);
  rationale.push(`base priority ${priority} from risk score ${input.riskScore} (§24)`);

  const verified = input.verificationStatus === "VERIFIED";
  const production = input.environment === "PRODUCTION" || input.environment === undefined;

  // §25: verified + KEV + internet-facing + production = the strongest
  // documented case → P0. Each missing leg weakens the escalation by
  // exactly one band so context always matters.
  if (input.kevListed) {
    const legs = [verified, !!input.internetExposed, production].filter(Boolean).length;
    if (legs === 3) {
      rationale.push("KEV-listed + VERIFIED + internet-facing + production → P0 (§25 strongest case)");
      priority = "P0";
    } else if (legs === 2) {
      const next = escalatePriority(priority, 1);
      rationale.push(`KEV-listed with ${legs}/3 strong-case legs → escalate ${priority} → ${next} (§25)`);
      priority = next;
    } else {
      rationale.push("KEV-listed but context is weak (unverified / internal / non-production) — no automatic P0 (§25)");
    }
  }

  if (input.epssScore !== undefined && input.epssScore >= 0.7 && verified) {
    const next = escalatePriority(priority, 1);
    if (next !== priority) rationale.push(`EPSS ${input.epssScore} ≥ 0.7 with VERIFIED status → escalate ${priority} → ${next} (§24)`);
    priority = next;
  }

  if (input.assetCriticality === "CRITICAL" && input.internetExposed) {
    const next = escalatePriority(priority, 1);
    if (next !== priority) rationale.push(`critical asset, internet-facing → escalate ${priority} → ${next} (§24)`);
    priority = next;
  }

  if (input.slaState === "OVERDUE") {
    const next = escalatePriority(priority, 1);
    if (next !== priority) rationale.push(`SLA OVERDUE → escalate ${priority} → ${next} (§24)`);
    priority = next;
  }

  // Unverified low-signal findings should not outrank verified work.
  if (input.verificationStatus === "UNVERIFIED" && !input.kevListed && priority === "P0") {
    priority = "P1";
    rationale.push("unverified finding capped at P1 — verification precedes top priority (§24)");
  }

  return { priority, rationale };
}

export const RemediationPrioritizationService = { prioritize };
