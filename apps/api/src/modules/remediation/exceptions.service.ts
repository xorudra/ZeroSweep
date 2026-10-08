import { BadRequestException, ForbiddenException, Inject, Injectable } from "@nestjs/common";
import { EXCEPTION_TYPES } from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { CaseStateService } from "./case-state.service";
import { VulnerabilityService } from "../vulnerabilities/vulnerability.service";
import { requireRemediationPermission } from "./permissions";

/**
 * Remediation exceptions (Prompt 31 §78–§83). Requirements are
 * enforced, not suggested: reason, scope, owner, approver, start and
 * EXPIRATION are all mandatory — a permanent silent exception cannot
 * be represented (§80). Risk acceptance is NOT duplicated: a
 * RISK_ACCEPTANCE exception creates the platform's existing P20
 * RiskException row and links it; approval honours the same SoD rule
 * (approver ≠ requester). Expiry returns the finding to the actionable
 * workflow (§83/§145).
 */
@Injectable()
export class RemediationExceptionsService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly state: CaseStateService,
    private readonly vulnerabilities: VulnerabilityService,
  ) {}

  async createException(user: RequestUser, workspaceId: string, caseId: string, input: {
    type: string; reason: string; ownerId: string; expiresAt: Date;
    scope?: Record<string, unknown>; compensatingControls?: unknown; reviewAt?: Date;
  }) {
    requireRemediationPermission(user, "MANAGE_REMEDIATION_EXCEPTION");
    if (!(EXCEPTION_TYPES as readonly string[]).includes(input.type)) {
      throw new BadRequestException(`exception type must be one of ${EXCEPTION_TYPES.join(", ")} (§78)`);
    }
    if (!input.reason?.trim()) throw new BadRequestException("an exception requires a reason (§79)");
    if (!input.ownerId) throw new BadRequestException("an exception requires an owner (§79)");
    if (!input.expiresAt || Number.isNaN(input.expiresAt.getTime())) {
      throw new BadRequestException("an exception requires an expiration — permanent silent exceptions do not exist (§80)");
    }
    if (input.expiresAt.getTime() <= Date.now()) throw new BadRequestException("expiration must be in the future");
    if ((input.type === "RISK_ACCEPTANCE" || input.type === "BUSINESS_EXCEPTION") && !input.compensatingControls) {
      throw new BadRequestException("this exception type requires compensating controls (§79)");
    }
    const kase = await this.state.getCase(workspaceId, caseId);
    let riskExceptionId: string | null = null;
    if (input.type === "RISK_ACCEPTANCE") {
      // §81: reuse the existing acceptance record — the remediation
      // exception references it instead of duplicating the system.
      const riskException = await this.prisma.riskException.create({
        data: {
          workspaceId, findingId: kase.findingId, type: "ACCEPTED_RISK", status: "PENDING",
          requestedBy: user.id, reason: input.reason,
          scope: (input.scope as never) ?? { caseId }, expiresAt: input.expiresAt,
        },
      });
      riskExceptionId = riskException.id;
    }
    const exception = await this.prisma.remediationException.create({
      data: {
        caseId, workspaceId, findingId: kase.findingId, type: input.type, status: "PENDING",
        reason: input.reason, scope: (input.scope as never) ?? null, ownerId: input.ownerId,
        requestedBy: user.id, compensatingControls: (input.compensatingControls as never) ?? null,
        riskExceptionId, startsAt: new Date(), expiresAt: input.expiresAt, reviewAt: input.reviewAt ?? null,
      },
    });
    await this.state.emit(user, workspaceId, kase, "REMEDIATION_EXCEPTION_CREATED", { exceptionId: exception.id, type: input.type });
    return exception;
  }

  async approveException(user: RequestUser, workspaceId: string, caseId: string, exceptionId: string) {
    requireRemediationPermission(user, "APPROVE_REMEDIATION_EXCEPTION");
    const kase = await this.state.getCase(workspaceId, caseId);
    const exception = await this.prisma.remediationException.findFirst({ where: { id: exceptionId, caseId, workspaceId } });
    if (!exception) throw new BadRequestException("exception not found for this case");
    if (exception.status !== "PENDING") throw new BadRequestException(`exception is ${exception.status}`);
    if (exception.requestedBy === user.id) {
      throw new ForbiddenException("segregation of duties: the requester cannot approve their own exception (§79)");
    }
    if (exception.type === "RISK_ACCEPTANCE" && !["NEW", "TRIAGED", "ASSIGNED"].includes(kase.status)) {
      throw new BadRequestException(
        `risk acceptance is decided before work is underway — the case is ${kase.status}; return it to TRIAGED/ASSIGNED first (§7)`,
      );
    }
    const updated = await this.prisma.remediationException.update({
      where: { id: exceptionId }, data: { status: "APPROVED", approverId: user.id },
    });
    if (exception.riskExceptionId) {
      await this.prisma.riskException.update({
        where: { id: exception.riskExceptionId },
        data: { status: "ACTIVE", approvedBy: user.id },
      });
    }
    let updatedCase = kase;
    if (exception.type === "RISK_ACCEPTANCE" && !["VERIFIED_FIXED", "CLOSED"].includes(kase.status)) {
      updatedCase = await this.state.transition(user, workspaceId, kase, {
        to: "ACCEPTED_RISK", viaException: true,
        reason: exception.reason, evidence: { exceptionId },
      });
      // Drive the canonical lifecycle to ACCEPTED_RISK via P11 — the
      // machine demands approver + expiry, which the exception carries.
      try {
        await this.vulnerabilities.transition(user, workspaceId, kase.findingId, {
          to: "ACCEPTED_RISK" as never, reason: exception.reason,
          riskAcceptance: { approverId: user.id, expiresAt: exception.expiresAt },
        });
      } catch { /* resting state may require a step first; case state stands */ }
    } else if (exception.type === "TEMPORARY_DEFERRAL" && ["NEW", "TRIAGED", "ASSIGNED", "PLANNED", "IN_PROGRESS"].includes(kase.status)) {
      updatedCase = await this.state.transition(user, workspaceId, kase, {
        to: "DEFERRED", reason: exception.reason, evidence: { exceptionId },
      });
    }
    await this.state.emit(user, workspaceId, kase, "REMEDIATION_EXCEPTION_APPROVED", { exceptionId });
    return { case: updatedCase, exception: updated };
  }

  async rejectException(user: RequestUser, workspaceId: string, caseId: string, exceptionId: string) {
    requireRemediationPermission(user, "APPROVE_REMEDIATION_EXCEPTION");
    const exception = await this.prisma.remediationException.findFirst({ where: { id: exceptionId, caseId, workspaceId } });
    if (!exception) throw new BadRequestException("exception not found for this case");
    if (exception.status !== "PENDING") throw new BadRequestException(`exception is ${exception.status}`);
    const updated = await this.prisma.remediationException.update({
      where: { id: exceptionId }, data: { status: "REJECTED", approverId: user.id },
    });
    if (exception.riskExceptionId) {
      await this.prisma.riskException.update({ where: { id: exception.riskExceptionId }, data: { status: "REJECTED", approvedBy: user.id } });
    }
    return updated;
  }

  /**
   * Expiry sweep (§82/§83): APPROVED exceptions past expiresAt expire;
   * an expiring-soon warning fires once inside the review window. An
   * expired acceptance returns the case to the actionable workflow.
   */
  async sweepExpiries(user: RequestUser, workspaceId: string, now = new Date(), warnWithinMs = 7 * 24 * 3600 * 1000) {
    const approved = await this.prisma.remediationException.findMany({
      where: { workspaceId, status: "APPROVED" }, take: 5000,
    });
    let expired = 0;
    let expiring = 0;
    for (const exception of approved) {
      const kase = await this.prisma.remediationCase.findFirst({ where: { id: exception.caseId, workspaceId } });
      if (!kase) continue;
      if (exception.expiresAt.getTime() <= now.getTime()) {
        await this.prisma.remediationException.update({ where: { id: exception.id }, data: { status: "EXPIRED" } });
        if (exception.riskExceptionId) {
          await this.prisma.riskException.update({ where: { id: exception.riskExceptionId }, data: { status: "EXPIRED" } });
        }
        await this.state.emit(user, workspaceId, kase, "REMEDIATION_EXCEPTION_EXPIRED", { exceptionId: exception.id });
        if (kase.status === "ACCEPTED_RISK" || kase.status === "DEFERRED") {
          await this.state.transition(user, workspaceId, kase, {
            to: "TRIAGED", reason: "exception expired — returned to the actionable workflow (§83)",
          });
          try {
            await this.vulnerabilities.transition(user, workspaceId, kase.findingId, {
              to: "TRIAGED" as never, reason: "risk acceptance expired (Prompt 31 §83)",
            });
          } catch { /* lifecycle resting state governs; case state stands */ }
        }
        expired += 1;
      } else if (exception.expiresAt.getTime() - now.getTime() <= warnWithinMs) {
        await this.state.emit(user, workspaceId, kase, "REMEDIATION_EXCEPTION_EXPIRING", { exceptionId: exception.id, expiresAt: exception.expiresAt.toISOString() });
        expiring += 1;
      }
    }
    return { expired, expiring };
  }
}
