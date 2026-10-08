import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import { isFeatureKey, isSafetyInvariantKey } from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";

/* eslint-disable @typescript-eslint/no-explicit-any */

export interface PlanEntitlementInput { featureKey: string; enabled: boolean; limit?: number | null; configuration?: Record<string, unknown> }

/**
 * Plan administration (Prompt 40 §6–§9). Platform-admin only at the
 * controller layer (§136 MANAGE_PRODUCT_PLANS). Plans are versioned
 * (§8): updating a plan creates a NEW PlanVersion; existing
 * subscriptions keep their historical version reference. Monetary
 * pricing is never stored on a plan (§257).
 */
@Injectable()
export class PlansService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  private validateEntitlements(entitlements: PlanEntitlementInput[]): void {
    for (const e of entitlements) {
      if (isSafetyInvariantKey(e.featureKey)) {
        throw new BadRequestException(`'${e.featureKey}' is a safety invariant, not an entitlement — safety cannot be entitled away (§16).`);
      }
      if (!isFeatureKey(e.featureKey)) throw new BadRequestException(`Unknown feature key '${e.featureKey}' (§10).`);
    }
  }

  async createPlan(actorId: string, input: { code: string; name: string; description?: string; productMode: string; entitlements: PlanEntitlementInput[]; quotas?: Record<string, number | null> }): Promise<any> {
    this.validateEntitlements(input.entitlements);
    const existing = await (this.prisma as any).productPlan.findUnique({ where: { code: input.code } });
    if (existing) throw new BadRequestException(`Plan code '${input.code}' already exists.`);
    const plan = await (this.prisma as any).productPlan.create({
      data: { code: input.code, name: input.name, description: input.description ?? null, productMode: input.productMode, status: "DRAFT" },
    });
    const version = await this.createVersion(plan.id, 1, input.entitlements, input.quotas ?? {});
    await this.audit.record({ actorId, action: "PLAN_CREATED", resourceType: "ProductPlan", resourceId: plan.id, metadata: { code: input.code, productMode: input.productMode } });
    return { ...plan, currentVersion: version };
  }

  private async createVersion(planId: string, version: number, entitlements: PlanEntitlementInput[], quotas: Record<string, number | null>): Promise<any> {
    const row = await (this.prisma as any).planVersion.create({ data: { planId, version, quotas } });
    for (const e of entitlements) {
      await (this.prisma as any).planEntitlement.create({
        data: { planVersionId: row.id, featureKey: e.featureKey, enabled: e.enabled, limit: e.limit ?? null, configuration: (e.configuration ?? null) as never },
      });
    }
    return row;
  }

  /** §8: a plan change is a new version; subscriptions are untouched. */
  async updatePlan(actorId: string, planId: string, input: { name?: string; description?: string; entitlements: PlanEntitlementInput[]; quotas?: Record<string, number | null> }): Promise<any> {
    this.validateEntitlements(input.entitlements);
    const plan = await (this.prisma as any).productPlan.findUnique({ where: { id: planId } });
    if (!plan) throw new NotFoundException("Plan not found.");
    const latest = await (this.prisma as any).planVersion.findFirst({ where: { planId }, orderBy: { version: "desc" } });
    const version = await this.createVersion(planId, (latest?.version ?? 0) + 1, input.entitlements, input.quotas ?? (latest?.quotas ?? {}));
    if (input.name || input.description) {
      await (this.prisma as any).productPlan.update({ where: { id: planId }, data: { name: input.name ?? plan.name, description: input.description ?? plan.description } });
    }
    await this.audit.record({ actorId, action: "PLAN_UPDATED", resourceType: "ProductPlan", resourceId: planId, metadata: { newVersion: version.version } });
    return version;
  }

  async setPlanStatus(actorId: string, planId: string, status: string): Promise<any> {
    const allowed = ["DRAFT", "ACTIVE", "DEPRECATED", "RETIRED"];
    if (!allowed.includes(status)) throw new BadRequestException(`Invalid plan status '${status}' (§7).`);
    const plan = await (this.prisma as any).productPlan.findUnique({ where: { id: planId } });
    if (!plan) throw new NotFoundException("Plan not found.");
    const updated = await (this.prisma as any).productPlan.update({ where: { id: planId }, data: { status } });
    if (status === "ACTIVE") {
      await this.audit.record({ actorId, action: "PLAN_ACTIVATED", resourceType: "ProductPlan", resourceId: planId, metadata: { code: plan.code } });
    }
    return updated;
  }

  async listPlans(): Promise<any[]> {
    const plans = await (this.prisma as any).productPlan.findMany({ orderBy: { code: "asc" } });
    const out = [];
    for (const plan of plans) {
      const latest = await (this.prisma as any).planVersion.findFirst({ where: { planId: plan.id }, orderBy: { version: "desc" } });
      out.push({ ...plan, latestVersion: latest });
    }
    return out;
  }

  async latestActiveVersion(planCode: string): Promise<any | null> {
    const plan = await (this.prisma as any).productPlan.findUnique({ where: { code: planCode } });
    if (!plan || plan.status !== "ACTIVE") return null;
    return (this.prisma as any).planVersion.findFirst({ where: { planId: plan.id }, orderBy: { version: "desc" } });
  }
}
