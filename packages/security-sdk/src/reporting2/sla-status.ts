/**
 * Prompt 37 §25: SLA status derivation for a finding.
 *
 * Derived from the STORED due date (written by the Prompt 20/31 SLA
 * engines from a VERSIONED policy) plus live exception/verification
 * facts. Deriving status never rewrites history: a policy change
 * produces a new SLA snapshot on the case/finding (§26); this function
 * only reads.
 */
export const SLA_STATUSES = ["ON_TRACK", "AT_RISK", "OVERDUE", "EXEMPT", "VERIFICATION_PENDING"] as const;
export type V2SlaStatus = (typeof SLA_STATUSES)[number];

export interface SlaStatusInput {
  dueAt?: Date | string | null;
  lifecycleStatus: string;
  /** An ACTIVE, unexpired exception covers this finding (§19). */
  hasActiveException?: boolean;
  /** A Prompt 31 verification is outstanding for the claimed fix. */
  verificationPending?: boolean;
  now: Date;
  /** Fraction of the total window that may elapse before AT_RISK. */
  atRiskAfterFraction?: number;
  createdAt?: Date | string | null;
}

const TERMINAL = new Set(["RESOLVED", "FALSE_POSITIVE", "DUPLICATE"]);

export function deriveSlaStatus(input: SlaStatusInput): V2SlaStatus {
  if (input.hasActiveException) return "EXEMPT";
  if (TERMINAL.has(input.lifecycleStatus)) return "ON_TRACK"; // closed work is never "overdue"
  if (input.verificationPending) return "VERIFICATION_PENDING";
  if (!input.dueAt) return "ON_TRACK"; // no SLA assigned — nothing to breach (never invented)
  const due = new Date(input.dueAt).getTime();
  const now = input.now.getTime();
  if (due < now) return "OVERDUE";
  if (input.createdAt) {
    const start = new Date(input.createdAt).getTime();
    const total = due - start;
    if (total > 0) {
      const elapsed = (now - start) / total;
      if (elapsed >= (input.atRiskAfterFraction ?? 0.75)) return "AT_RISK";
    }
  } else if (due - now < 48 * 3_600_000) {
    return "AT_RISK";
  }
  return "ON_TRACK";
}
