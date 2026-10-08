import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { AuditService } from "../audit/audit.service";

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Platform control plane data (Prompt 40 §95–§106).
 *
 * Views are METADATA ONLY: status, plan, usage totals, limits, health
 * metadata, created date, region, release/version (§106). There is no
 * code path here — or anywhere in the platform admin surface — that
 * returns user passwords (§104), raw integration secrets (§105),
 * finding evidence or customer content.
 *
 * Support access (§100–§103) is a controlled session record: reason,
 * operator, tenant, scope, expiry, audit, tenant-approval flag and a
 * visible indicator. Sessions auto-expire. Unrestricted silent
 * impersonation does not exist (§99).
 */
@Injectable()
export class PlatformControlDataService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  /** §106 safe organization projection. */
  private projectOrganization(org: any, extra: Record<string, unknown> = {}): Record<string, unknown> {
    return {
      id: org.id, name: org.name, slug: org.slug, status: org.status,
      lifecycleStatus: org.lifecycleStatus, legalHold: org.legalHold, isDemo: org.isDemo,
      region: org.dataRegion ?? null, createdAt: org.createdAt, ...extra,
    };
  }

  async listOrganizations(): Promise<any[]> {
    const orgs = await (this.prisma as any).organization.findMany({ orderBy: { createdAt: "desc" }, take: 200 });
    const out = [];
    for (const org of orgs) {
      const sub = await (this.prisma as any).subscription.findFirst({ where: { organizationId: org.id }, orderBy: { createdAt: "desc" }, include: { planVersion: { include: { plan: true } } } });
      out.push(this.projectOrganization(org, {
        plan: sub ? { code: sub.planVersion?.plan?.code ?? null, status: sub.status } : null,
      }));
    }
    return out;
  }

  async getOrganization(organizationId: string): Promise<any> {
    const org = await (this.prisma as any).organization.findUnique({ where: { id: organizationId } });
    if (!org) throw new NotFoundException("Organization not found.");
    const [workspaces, members, sub, trial, onboarding] = await Promise.all([
      (this.prisma as any).workspace.count({ where: { organizationId } }),
      (this.prisma as any).membership.count({ where: { organizationId, status: "ACTIVE" } }),
      (this.prisma as any).subscription.findFirst({ where: { organizationId }, orderBy: { createdAt: "desc" }, include: { planVersion: { include: { plan: true } } } }),
      (this.prisma as any).productTrial.findFirst({ where: { organizationId }, orderBy: { createdAt: "desc" } }),
      (this.prisma as any).organizationOnboarding.findUnique({ where: { organizationId } }),
    ]);
    return this.projectOrganization(org, {
      workspaceCount: workspaces, memberCount: members,
      plan: sub ? { code: sub.planVersion?.plan?.code ?? null, status: sub.status, planVersionId: sub.planVersionId } : null,
      trial: trial ? { status: trial.status, expiresAt: trial.expiresAt } : null,
      onboarding: onboarding ? { status: onboarding.status, currentStep: onboarding.currentStep } : null,
    });
  }

  async listSubscriptions(): Promise<any[]> {
    return (this.prisma as any).subscription.findMany({ orderBy: { createdAt: "desc" }, take: 200, include: { planVersion: { include: { plan: true } } } });
  }

  async listLicenses(): Promise<any[]> {
    const rows = await (this.prisma as any).productLicense.findMany({ orderBy: { installedAt: "desc" }, take: 200 });
    // §105: signature material is never exposed to the platform UI.
    return rows.map(({ signature: _s, ...rest }: any) => rest);
  }

  async listTrials(): Promise<any[]> {
    return (this.prisma as any).productTrial.findMany({ orderBy: { createdAt: "desc" }, take: 200 });
  }

  async usageTotals(): Promise<any[]> {
    const aggregates = await (this.prisma as any).usageAggregate.findMany({ where: { granularity: "BILLING_PERIOD" }, take: 500 });
    return aggregates;
  }

  // ---- Support access (§100–§103) ------------------------------------------

  async createSupportSession(operator: { id: string }, input: { organizationId: string; reason: string; scope: { areas: string[] }; expiresInHours: number; tenantApproved: boolean }): Promise<any> {
    const org = await (this.prisma as any).organization.findUnique({ where: { id: input.organizationId } });
    if (!org) throw new NotFoundException("Organization not found.");
    const session = await (this.prisma as any).supportAccessSession.create({
      data: {
        organizationId: input.organizationId, operatorId: operator.id, reason: input.reason,
        scope: input.scope as never, status: input.tenantApproved ? "ACTIVE" : "PENDING_APPROVAL",
        tenantApproved: input.tenantApproved, startedAt: input.tenantApproved ? new Date() : null,
        expiresAt: new Date(Date.now() + input.expiresInHours * 3600_000),
      },
    });
    await this.audit.record({
      actorId: operator.id, organizationId: input.organizationId, action: "SUPPORT_ACCESS_STARTED",
      resourceType: "SupportAccessSession", resourceId: session.id,
      metadata: { reason: input.reason, areas: input.scope.areas, expiresAt: session.expiresAt.toISOString(), tenantApproved: input.tenantApproved },
    });
    return session;
  }

  async approveSupportSession(organizationId: string, sessionId: string, approverId: string): Promise<any> {
    const session = await (this.prisma as any).supportAccessSession.findFirst({ where: { id: sessionId, organizationId } });
    if (!session) throw new NotFoundException("Support session not found.");
    if (session.status !== "PENDING_APPROVAL") throw new BadRequestException(`Support session is ${session.status}; only PENDING_APPROVAL can be approved.`);
    if (session.expiresAt < new Date()) throw new BadRequestException("Support session has already expired (§103).");
    return (this.prisma as any).supportAccessSession.update({
      where: { id: sessionId },
      data: { status: "ACTIVE", tenantApproved: true, approvedById: approverId, startedAt: new Date() },
    });
  }

  async endSupportSession(operatorId: string, sessionId: string): Promise<any> {
    const session = await (this.prisma as any).supportAccessSession.findUnique({ where: { id: sessionId } });
    if (!session) throw new NotFoundException("Support session not found.");
    const updated = await (this.prisma as any).supportAccessSession.update({
      where: { id: sessionId }, data: { status: "ENDED", endedAt: new Date() },
    });
    await this.audit.record({
      actorId: operatorId, organizationId: session.organizationId, action: "SUPPORT_ACCESS_ENDED",
      resourceType: "SupportAccessSession", resourceId: sessionId, metadata: {},
    });
    return updated;
  }

  /** §224: an expired session grants nothing. */
  async requireActiveSupportSession(sessionId: string, organizationId: string): Promise<any> {
    const session = await (this.prisma as any).supportAccessSession.findFirst({ where: { id: sessionId, organizationId } });
    if (!session || session.status !== "ACTIVE" || session.expiresAt < new Date()) {
      throw new BadRequestException("Support access session is not active (expired, pending approval or ended) — access denied (§103/§224).");
    }
    return session;
  }

  async listSupportSessions(organizationId?: string): Promise<any[]> {
    return (this.prisma as any).supportAccessSession.findMany({
      where: organizationId ? { organizationId } : {}, orderBy: { createdAt: "desc" }, take: 200,
    });
  }

  /** §225: complete audit trail for support access in an organization. */
  async supportAuditTrail(organizationId: string): Promise<any[]> {
    return (this.prisma as any).auditLog.findMany({
      where: { organizationId, resourceType: "SupportAccessSession" }, orderBy: { createdAt: "asc" }, take: 500,
    });
  }
}
