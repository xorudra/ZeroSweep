import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  evaluateRemediationTransition, type RemediationStatus,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { AuditService } from "../audit/audit.service";
import { EventsService } from "../integrations/events/events.service";
import type { RequestUser } from "../../common/decorators/auth.decorators";

export type CaseRow = Awaited<ReturnType<PrismaClientLike["remediationCase"]["findFirstOrThrow"]>>;
export type FindingRow = Awaited<ReturnType<PrismaClientLike["finding"]["findFirstOrThrow"]>>;

const AUDIT_BY_EVENT: Record<string, string> = {
  REMEDIATION_CASE_CREATED: "REMEDIATION_CASE_CREATED",
  REMEDIATION_TRIAGED: "REMEDIATION_TRIAGED",
  REMEDIATION_ASSIGNED: "REMEDIATION_ASSIGNED",
  REMEDIATION_REASSIGNED: "REMEDIATION_REASSIGNED",
  REMEDIATION_PLAN_CREATED: "REMEDIATION_PLAN_CREATED",
  REMEDIATION_SLA_ASSIGNED: "REMEDIATION_SLA_ASSIGNED",
  REMEDIATION_SLA_PAUSED: "REMEDIATION_SLA_PAUSED",
  REMEDIATION_SLA_BREACHED: "REMEDIATION_SLA_BREACHED",
  REMEDIATION_FIX_CLAIMED: "REMEDIATION_FIX_CLAIMED",
  REMEDIATION_VERIFICATION_REQUESTED: "REMEDIATION_VERIFICATION_REQUESTED",
  REMEDIATION_VERIFICATION_STARTED: "REMEDIATION_VERIFICATION_STARTED",
  REMEDIATION_VERIFICATION_PASSED: "REMEDIATION_VERIFICATION_PASSED",
  REMEDIATION_VERIFICATION_FAILED: "REMEDIATION_VERIFICATION_FAILED",
  REMEDIATION_VERIFICATION_INCONCLUSIVE: "REMEDIATION_VERIFICATION_INCONCLUSIVE",
  REMEDIATION_VERIFIED_FIXED: "REMEDIATION_VERIFIED_FIXED",
  REMEDIATION_CLOSED: "REMEDIATION_CLOSED",
  VULNERABILITY_REGRESSION_DETECTED: "VULNERABILITY_REGRESSION_DETECTED",
  REMEDIATION_EXCEPTION_CREATED: "REMEDIATION_EXCEPTION_CREATED",
  REMEDIATION_EXCEPTION_APPROVED: "REMEDIATION_EXCEPTION_APPROVED",
  REMEDIATION_EXCEPTION_EXPIRED: "REMEDIATION_EXCEPTION_EXPIRED",
  REMEDIATION_CAMPAIGN_CREATED: "REMEDIATION_CAMPAIGN_CREATED",
};

/**
 * The shared state primitive for Prompt 31: load a case tenant-scoped,
 * apply a GUARDED transition, and record all four side effects every
 * state change owes (§119/§123/§125): status history row (§8/§9),
 * audit entry, transactional-outbox event, and the caller-visible
 * result. Domain services (triage, SLA, tickets, verification,
 * closure, exceptions, regression) build on this — none of them writes
 * case status directly.
 */
@Injectable()
export class CaseStateService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly events: EventsService,
  ) {}

  async getCase(workspaceId: string, caseId: string): Promise<CaseRow> {
    const row = await this.prisma.remediationCase.findFirst({ where: { id: caseId, workspaceId } });
    if (!row) throw new NotFoundException("remediation case not found in this workspace");
    return row as CaseRow;
  }

  async getFinding(workspaceId: string, findingId: string): Promise<FindingRow> {
    const finding = await this.prisma.finding.findFirst({ where: { id: findingId, workspaceId } });
    if (!finding) throw new NotFoundException("finding not found in this workspace");
    return finding as FindingRow;
  }

  /** Apply a guarded transition (§7/§119). Throws on invalid moves —
   *  a rejected transition writes NOTHING. */
  async transition(
    user: RequestUser,
    workspaceId: string,
    kase: CaseRow,
    input: {
      to: RemediationStatus;
      reason?: string;
      evidence?: unknown;
      viaVerification?: boolean;
      viaClosure?: boolean;
      viaFixClaim?: boolean;
      viaException?: boolean;
      event?: string;
      extraData?: Record<string, unknown>;
    },
  ): Promise<CaseRow> {
    const verdict = evaluateRemediationTransition({
      from: kase.status as RemediationStatus, to: input.to,
      reason: input.reason, evidence: input.evidence,
      viaVerification: input.viaVerification, viaClosure: input.viaClosure,
      viaFixClaim: input.viaFixClaim, viaException: input.viaException,
    });
    if (!verdict.ok) throw new BadRequestException(verdict.error);
    const data: Record<string, unknown> = { status: input.to, ...(input.extraData ?? {}) };
    if (input.to === "VERIFIED_FIXED") data.verifiedFixedAt = new Date();
    if (input.to === "CLOSED") data.closedAt = new Date();
    const updated = await this.prisma.remediationCase.update({ where: { id: kase.id }, data: data as never });
    await this.prisma.remediationStatusHistory.create({
      data: {
        caseId: kase.id, workspaceId, fromStatus: kase.status, toStatus: input.to,
        actorId: user.id, reason: input.reason ?? null, evidence: (input.evidence as never) ?? null,
      },
    });
    const event = input.event ?? this.eventFor(input.to);
    if (event) await this.emit(user, workspaceId, kase, event, { from: kase.status, to: input.to, reason: input.reason ?? null });
    return updated as CaseRow;
  }

  /** Record an audit entry + outbox event without a status change. */
  async emit(
    user: { id: string; organizationId: string },
    workspaceId: string,
    kase: { id: string; findingId: string },
    event: string,
    metadata: Record<string, unknown> = {},
  ): Promise<void> {
    const action = AUDIT_BY_EVENT[event];
    if (action) {
      await this.audit.record({
        actorId: user.id, organizationId: user.organizationId, workspaceId,
        action: action as never, resourceType: "REMEDIATION_CASE", resourceId: kase.id,
        metadata: { findingId: kase.findingId, ...metadata },
      });
    }
    await this.events.publish({
      workspaceId, eventType: event, resourceType: "REMEDIATION_CASE", resourceId: kase.id,
      payload: { caseId: kase.id, findingId: kase.findingId, ...metadata },
    });
  }

  /** Publish an outbox event for a non-case resource (campaigns). */
  async publishEvent(workspaceId: string, event: string, resourceType: string, resourceId: string, payload: Record<string, unknown>): Promise<void> {
    await this.events.publish({ workspaceId, eventType: event, resourceType, resourceId, payload });
  }

  private eventFor(to: RemediationStatus): string | null {
    switch (to) {
      case "TRIAGED": return "REMEDIATION_TRIAGED";
      case "ASSIGNED": return "REMEDIATION_ASSIGNED";
      case "VERIFIED_FIXED": return "REMEDIATION_VERIFIED_FIXED";
      case "CLOSED": return "REMEDIATION_CLOSED";
      case "FIX_CLAIMED": return "REMEDIATION_FIX_CLAIMED";
      case "VERIFICATION_PENDING": return "REMEDIATION_VERIFICATION_REQUESTED";
      default: return null;
    }
  }
}
