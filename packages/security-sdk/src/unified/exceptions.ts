/**
 * Risk exceptions (Prompt 20 §31–§33).
 *
 * An exception is a RECORDED, APPROVED, EXPIRING decision — never a
 * silent state. Types: ACCEPTED_RISK / FALSE_POSITIVE /
 * COMPENSATING_CONTROL / TEMPORARY_EXCEPTION. High-risk exceptions
 * require a SEPARATE approver (§32: requestedBy !== approvedBy). On
 * expiry the finding returns to review (§33) and an audit event is
 * produced by the caller — expiry never deletes the exception record.
 */

export type RiskExceptionType = "ACCEPTED_RISK" | "FALSE_POSITIVE" | "COMPENSATING_CONTROL" | "TEMPORARY_EXCEPTION";
export type RiskExceptionStatus = "PENDING" | "ACTIVE" | "REJECTED" | "EXPIRED";

export interface RiskExceptionView {
  id: string;
  findingId: string;
  type: RiskExceptionType;
  status: RiskExceptionStatus;
  requestedBy: string;
  approvedBy?: string | null;
  reason: string;
  expiresAt?: Date | string | null;
  createdAt: Date | string;
}

/** Severities/priorities where §32 mandates separation of duties. */
export function exceptionRequiresSeparateApprover(input: { severity: string; priority?: string | null }): boolean {
  return input.severity === "CRITICAL" || input.severity === "HIGH" || input.priority === "P0" || input.priority === "P1";
}

export interface ExceptionApprovalInput {
  exception: RiskExceptionView;
  approverId: string;
  severity: string;
  priority?: string | null;
  now?: Date;
}

export type ExceptionApprovalResult = { ok: true } | { ok: false; error: string };

export function evaluateExceptionApproval(input: ExceptionApprovalInput): ExceptionApprovalResult {
  const { exception: ex, approverId } = input;
  if (ex.status !== "PENDING") return { ok: false, error: `exception is ${ex.status}, not PENDING` };
  if (!ex.reason?.trim()) return { ok: false, error: "exception requires a recorded reason (§32)" };
  if (exceptionRequiresSeparateApprover(input) && approverId === ex.requestedBy) {
    return { ok: false, error: "high-risk exceptions require a separate approver (§32) — requester cannot approve their own exception" };
  }
  if (ex.expiresAt) {
    const exp = new Date(ex.expiresAt);
    if (!Number.isNaN(exp.getTime()) && exp <= (input.now ?? new Date())) {
      return { ok: false, error: "exception already expired — file a new request (§33)" };
    }
  }
  return { ok: true };
}

/** §33: expired ACTIVE exceptions stop applying and return the finding
 *  to review. Callers persist status=EXPIRED + a TRIAGED lifecycle move
 *  + the RISK_EXCEPTION_EXPIRED audit event. */
export function isExceptionExpired(ex: RiskExceptionView, now: Date = new Date()): boolean {
  if (ex.status !== "ACTIVE" || !ex.expiresAt) return false;
  const exp = new Date(ex.expiresAt);
  return !Number.isNaN(exp.getTime()) && exp <= now;
}

export function exceptionIsActive(ex: RiskExceptionView, now: Date = new Date()): boolean {
  return ex.status === "ACTIVE" && !isExceptionExpired(ex, now);
}
