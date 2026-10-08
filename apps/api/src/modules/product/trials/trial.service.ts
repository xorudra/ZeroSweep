import { BadRequestException, Inject, Injectable } from "@nestjs/common";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import { ProductConfigService } from "../product-config.service";
import { EntitlementService } from "../entitlements/entitlement.service";

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Product trials (Prompt 40 §54–§57). A trial grants a plan version's
 * entitlements for a bounded window. On expiry, trial-only features are
 * restricted and customer data is preserved (§57/§222) — expiry never
 * deletes anything.
 *
 * Abuse controls (§56): one active trial per organization, an
 * organization that already consumed a trial cannot start another, and
 * trials bind to the verified organization owner account. No invasive
 * device fingerprinting is performed.
 */
@Injectable()
export class TrialService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly config: ProductConfigService,
    private readonly entitlements: EntitlementService,
  ) {}

  async startTrial(organizationId: string, planVersionId: string, actorId?: string): Promise<any> {
    const existing = await (this.prisma as any).productTrial.findFirst({ where: { organizationId } });
    if (existing?.status === "ACTIVE") throw new BadRequestException("Organization already has an active trial (§56).");
    if (existing) throw new BadRequestException("Organization has already consumed its trial (§56).");
    const expiresAt = new Date(Date.now() + this.config.trialDays() * 86_400_000);
    const trial = await (this.prisma as any).productTrial.create({
      data: { organizationId, planVersionId, status: "ACTIVE", expiresAt },
    });
    this.entitlements.invalidate(organizationId);
    await this.audit.record({ actorId, organizationId, action: "TRIAL_STARTED", resourceType: "ProductTrial", resourceId: trial.id, metadata: { expiresAt: expiresAt.toISOString() } });
    return trial;
  }

  async getForOrganization(organizationId: string): Promise<any | null> {
    return (this.prisma as any).productTrial.findFirst({ where: { organizationId }, orderBy: { createdAt: "desc" } });
  }

  /** Expiry sweep (invoked by the scheduler/operator tick): TRIAL_EXPIRED audit, data preserved. */
  async expireTrials(now = new Date()): Promise<number> {
    const due = await (this.prisma as any).productTrial.findMany({ where: { status: "ACTIVE", expiresAt: { lte: now } } });
    let count = 0;
    for (const trial of due) {
      await (this.prisma as any).productTrial.update({ where: { id: trial.id }, data: { status: "EXPIRED" } });
      const sub = await (this.prisma as any).subscription.findFirst({ where: { organizationId: trial.organizationId, status: "TRIALING" } });
      if (sub) {
        await (this.prisma as any).subscription.update({ where: { id: sub.id }, data: { status: "EXPIRED" } });
      }
      this.entitlements.invalidate(trial.organizationId);
      await this.audit.record({ organizationId: trial.organizationId, action: "TRIAL_EXPIRED", resourceType: "ProductTrial", resourceId: trial.id, metadata: { dataPreserved: true } });
      count++;
    }
    return count;
  }

  async markConverted(organizationId: string): Promise<void> {
    const trial = await this.getForOrganization(organizationId);
    if (trial && trial.status === "ACTIVE") {
      await (this.prisma as any).productTrial.update({ where: { id: trial.id }, data: { status: "CONVERTED", conversionStatus: "CONVERTED" } });
    }
  }
}
