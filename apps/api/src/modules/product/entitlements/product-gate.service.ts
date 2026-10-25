import { BadRequestException, Inject, Injectable } from "@nestjs/common";
import { isProtectedTarget, lifecycleAllowsNewWork, type FeatureKey } from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import { EntitlementService } from "./entitlement.service";
import { QuotaEnforcementService } from "../quotas/quota.service";
import { UsageMeteringService } from "../usage/usage.service";
import { AbusePreventionService } from "../abuse/abuse.service";

/* eslint-disable @typescript-eslint/no-explicit-any */

/** Map an assessment profile to its product feature (§10). */
export function featureForProfile(profile: string): FeatureKey {
  const p = (profile ?? "").toUpperCase();
  if (p.includes("API")) return "API_VAPT";
  if (p.includes("NETWORK")) return "NETWORK_VAPT";
  if (p.includes("MOBILE")) return "MOBILE_VAPT";
  if (p.includes("BINARY")) return "BINARY_ANALYSIS";
  if (p.includes("KUBERNETES")) return "KUBERNETES_SECURITY";
  if (p.includes("CONTAINER")) return "CONTAINER_SECURITY";
  if (p.includes("CLOUD")) return "CLOUD_SECURITY";
  if (p.includes("CODE") || p.includes("SAST")) return "SAST";
  return "WEB_VAPT";
}

/**
 * Product gate at scan start (Prompt 40 §12/§52/§87/§171/§173/§178).
 *
 * Layered AFTER the Prompt 38 platform gate and BESIDE — never instead
 * of — the authorization gate (verified target + approved assessment +
 * scope + policy). The product gate can only ever REFUSE a scan that
 * the safety gates allowed; it can never allow one they refused, and
 * no tier raises the platform safety ceiling (§175).
 *
 * Enforcement is active for organizations carrying product state
 * (subscription/trial/license); see EntitlementService.
 */
@Injectable()
export class ProductGateService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly entitlements: EntitlementService,
    private readonly quotas: QuotaEnforcementService,
    private readonly usage: UsageMeteringService,
    private readonly abuse: AbusePreventionService,
  ) {}

  async assertScanAllowed(input: { organizationId: string; userId: string; workspaceId: string; targetValue: string; profile: string }): Promise<void> {
    const org = await (this.prisma as any).organization.findUnique({ where: { id: input.organizationId } });
    if (!org) return; // tenant resolution upstream owns this failure

    if (org.isDemo) {
      throw new BadRequestException("Scan refused: demo organizations hold synthetic data only and cannot start real scans (DEMO_MODE, §178).");
    }
    if (!lifecycleAllowsNewWork(org.lifecycleStatus ?? "ACTIVE")) {
      throw new BadRequestException(`Scan refused: organization lifecycle is ${org.lifecycleStatus}; new security work is suspended while read/export/admin access remain available (§87).`);
    }
    if (isProtectedTarget(input.targetValue)) {
      await this.abuse.recordSignal(input.organizationId, "PROTECTED_TARGET_ATTEMPT", { profile: input.profile });
      await this.audit.record({
        actorId: input.userId, organizationId: input.organizationId, workspaceId: input.workspaceId,
        action: "POLICY_DENIED", resourceType: "Assessment",
        metadata: { reasonCode: "PROTECTED_TARGET", reason: "target is protected platform infrastructure (§173)" },
      }).catch(() => undefined);
      throw new BadRequestException("Scan refused: target is protected platform infrastructure (PROTECTED_TARGET, §173).");
    }
    if (await this.abuse.scanCreationBlocked(input.organizationId)) {
      throw new BadRequestException("Scan refused: scan creation is temporarily blocked pending abuse-signal review (§171). Signals are indicators, not proof of intent (§172) — contact platform operations.");
    }

    const { enforcementActive } = await this.entitlements.getEffectiveEntitlements(input.organizationId);
    if (enforcementActive) {
      await this.entitlements.requireFeature(input.organizationId, featureForProfile(input.profile));
      await this.quotas.check(input.organizationId, "MONTHLY_SCANS", 1, input.userId);
      await this.quotas.check(input.organizationId, "CONCURRENT_SCANS", 1, input.userId);
    }
  }

  /** §38–§42: meter a started scan exactly once per scan id. */
  async recordScanUsage(input: { organizationId: string; workspaceId: string; scanId: string; profile: string }): Promise<void> {
    const feature = featureForProfile(input.profile);
    const metric = feature === "API_VAPT" ? "API_SCAN_JOBS" : feature === "NETWORK_VAPT" ? "NETWORK_SCAN_JOBS" : feature === "WEB_VAPT" ? "WEB_SCAN_JOBS" : "SCAN_JOBS";
    await this.usage.record(input.organizationId, {
      workspaceId: input.workspaceId, metric: "SCAN_JOBS", quantity: 1,
      source: "orchestration", reference: input.scanId, idempotencyKey: `scan:${input.scanId}:SCAN_JOBS`,
    }).catch(() => undefined);
    if (metric !== "SCAN_JOBS") {
      await this.usage.record(input.organizationId, {
        workspaceId: input.workspaceId, metric, quantity: 1,
        source: "orchestration", reference: input.scanId, idempotencyKey: `scan:${input.scanId}:${metric}`,
      }).catch(() => undefined);
    }
  }
}
