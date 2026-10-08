import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import { computeDowngradeImpact } from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import { EntitlementService } from "../entitlements/entitlement.service";
import { QuotaEnforcementService } from "../quotas/quota.service";

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Subscriptions (Prompt 40 §17/§18) and plan changes (§113–§118).
 * Upgrades apply deterministically and immediately. Downgrades REQUIRE
 * an impact preview acknowledgement, never delete data (§116), and
 * leave the organization in an OVER_LIMIT state when usage exceeds the
 * new plan (§117) — existing data stays readable/exportable while new
 * over-limit creation is blocked by the quota service (§118).
 */
@Injectable()
export class SubscriptionService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly entitlements: EntitlementService,
    private readonly quotas: QuotaEnforcementService,
  ) {}

  async getForOrganization(organizationId: string): Promise<any | null> {
    return (this.prisma as any).subscription.findFirst({
      where: { organizationId }, orderBy: { createdAt: "desc" }, include: { planVersion: { include: { plan: true } } },
    });
  }

  async create(actorId: string, input: { organizationId: string; planVersionId: string; status?: string; trialEndsAt?: Date | null; externalBillingReference?: string | null }): Promise<any> {
    const version = await (this.prisma as any).planVersion.findUnique({ where: { id: input.planVersionId } });
    if (!version) throw new NotFoundException("Plan version not found.");
    const now = new Date();
    const periodEnd = new Date(now);
    periodEnd.setUTCMonth(periodEnd.getUTCMonth() + 1);
    const sub = await (this.prisma as any).subscription.create({
      data: {
        organizationId: input.organizationId,
        planVersionId: input.planVersionId,
        status: input.status ?? "ACTIVE",
        startedAt: now,
        currentPeriodStart: now,
        currentPeriodEnd: periodEnd,
        trialEndsAt: input.trialEndsAt ?? null,
        externalBillingReference: input.externalBillingReference ?? null,
      },
    });
    await this.quotas.materializePolicies(input.organizationId, (version.quotas ?? {}) as Record<string, number | null>, "PLAN");
    this.entitlements.invalidate(input.organizationId);
    await this.audit.record({ actorId, organizationId: input.organizationId, action: "SUBSCRIPTION_CREATED", resourceType: "Subscription", resourceId: sub.id, metadata: { planVersionId: input.planVersionId, status: sub.status } });
    return sub;
  }

  /** §113: upgrade applies new entitlements deterministically, immediately. */
  async upgrade(actorId: string, organizationId: string, newPlanVersionId: string): Promise<any> {
    const sub = await this.getForOrganization(organizationId);
    if (!sub) throw new NotFoundException("No subscription to upgrade.");
    const version = await (this.prisma as any).planVersion.findUnique({ where: { id: newPlanVersionId } });
    if (!version) throw new NotFoundException("Plan version not found.");
    const updated = await (this.prisma as any).subscription.update({
      where: { id: sub.id },
      data: { planVersionId: newPlanVersionId, status: sub.status === "TRIALING" ? "ACTIVE" : sub.status },
    });
    await this.quotas.materializePolicies(organizationId, (version.quotas ?? {}) as Record<string, number | null>, "PLAN");
    this.entitlements.invalidate(organizationId);
    await this.audit.record({ actorId, organizationId, action: "SUBSCRIPTION_UPDATED", resourceType: "Subscription", resourceId: sub.id, metadata: { change: "UPGRADE", fromPlanVersionId: sub.planVersionId, toPlanVersionId: newPlanVersionId } });
    return updated;
  }

  /** §115: impact preview for a prospective downgrade. */
  async previewDowngrade(organizationId: string, newPlanVersionId: string): Promise<any> {
    const version = await (this.prisma as any).planVersion.findUnique({ where: { id: newPlanVersionId }, include: { entitlements: true } });
    if (!version) throw new NotFoundException("Plan version not found.");
    const { entitlements } = await this.entitlements.getEffectiveEntitlements(organizationId);
    const newKeys = new Set((version.entitlements as any[]).filter((e) => e.enabled).map((e) => e.featureKey));
    const disabledFeatures = entitlements.filter((e) => e.enabled && !newKeys.has(e.featureKey)).map((e) => e.featureKey);
    const newLimits = (version.quotas ?? {}) as Record<string, number | null>;
    const usage: Record<string, number> = {};
    for (const dimension of Object.keys(newLimits)) {
      usage[dimension] = await this.quotas.getCurrentUsage(organizationId, dimension);
    }
    const scheduled = await (this.prisma as any).scan.count({ where: { workspaceId: { in: await this.workspaceIds(organizationId) }, status: { in: ["QUEUED", "RUNNING"] } } }).catch(() => 0);
    const impact = computeDowngradeImpact({ usage, newLimits, disabledFeatures, runningScheduledJobs: scheduled });
    return { planVersionId: newPlanVersionId, impact };
  }

  private async workspaceIds(organizationId: string): Promise<string[]> {
    const rows = await (this.prisma as any).workspace.findMany({ where: { organizationId }, select: { id: true } });
    return rows.map((r: any) => r.id);
  }

  /** §114: downgrade applies ONLY with the impact preview acknowledged. Data is never deleted (§116). */
  async downgrade(actorId: string, organizationId: string, newPlanVersionId: string, impactAcknowledged: boolean): Promise<any> {
    if (!impactAcknowledged) {
      throw new BadRequestException("Downgrade requires reviewing the impact preview first (§114/§115). Re-submit with impactAcknowledged=true.");
    }
    const sub = await this.getForOrganization(organizationId);
    if (!sub) throw new NotFoundException("No subscription to downgrade.");
    const version = await (this.prisma as any).planVersion.findUnique({ where: { id: newPlanVersionId } });
    if (!version) throw new NotFoundException("Plan version not found.");
    const { impact } = await this.previewDowngrade(organizationId, newPlanVersionId);
    const updated = await (this.prisma as any).subscription.update({ where: { id: sub.id }, data: { planVersionId: newPlanVersionId } });
    await this.quotas.materializePolicies(organizationId, (version.quotas ?? {}) as Record<string, number | null>, "PLAN");
    this.entitlements.invalidate(organizationId);
    await this.audit.record({ actorId, organizationId, action: "SUBSCRIPTION_UPDATED", resourceType: "Subscription", resourceId: sub.id, metadata: { change: "DOWNGRADE", toPlanVersionId: newPlanVersionId, overLimit: impact.resultsInOverLimit, dataDeleted: false } });
    return { subscription: updated, impact, overLimit: impact.resultsInOverLimit };
  }

  /** §88: cancellation marks intent; data/history are preserved. */
  async cancel(actorId: string, organizationId: string, atPeriodEnd: boolean): Promise<any> {
    const sub = await this.getForOrganization(organizationId);
    if (!sub) throw new NotFoundException("No subscription to cancel.");
    const updated = await (this.prisma as any).subscription.update({
      where: { id: sub.id },
      data: atPeriodEnd
        ? { cancelAtPeriodEnd: true }
        : { status: "CANCELLED", cancelledAt: new Date(), cancelAtPeriodEnd: false },
    });
    this.entitlements.invalidate(organizationId);
    await this.audit.record({ actorId, organizationId, action: "SUBSCRIPTION_CANCELLED", resourceType: "Subscription", resourceId: sub.id, metadata: { atPeriodEnd, dataDeleted: false } });
    return updated;
  }
}
