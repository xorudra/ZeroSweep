import { ForbiddenException, Inject, Injectable } from "@nestjs/common";
import {
  computeEffectiveEntitlements, evaluateLicense, findEntitlement, isSafetyInvariantKey,
  type EffectiveEntitlement, type EntitlementGrant, type FeatureKey,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { ProductConfigService } from "../product-config.service";

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * EntitlementService (Prompt 40 §13). Backend authority for feature
 * access (§12): controllers call requireFeature(); the UI only reflects
 * the result.
 *
 * Applicability rule (documented, honest): entitlement enforcement is
 * ACTIVE for an organization once it carries product state (a
 * subscription, an active/expired trial, or an installed license) —
 * which is always the case for SaaS-provisioned tenants (§82). An
 * organization with no product state is a pre-productization tenant of
 * this deployment and is governed by the deployment's own controls
 * (RBAC, scope, policy, platform ceilings), exactly as in Prompts 1–39.
 *
 * Cache (§241–§243): effective entitlements are cached per organization
 * with a key that includes plan version, license id and the override
 * watermark, so a plan/license/override change invalidates correctly
 * and one tenant's cache entry can never serve another tenant.
 */
@Injectable()
export class EntitlementService {
  private cache = new Map<string, { key: string; value: EffectiveEntitlement[]; enforcementActive: boolean }>();

  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly config: ProductConfigService,
  ) {}

  invalidate(organizationId: string): void {
    this.cache.delete(organizationId);
  }

  private async grantsForPlanVersion(planVersionId: string): Promise<EntitlementGrant[]> {
    const rows = await (this.prisma as any).planEntitlement.findMany({ where: { planVersionId } });
    return rows.map((r: any) => ({ featureKey: r.featureKey as FeatureKey, enabled: r.enabled, limit: r.limit ?? null }));
  }

  /** License layer grants, only when the installed license's paid capabilities are active (§35). */
  private async licenseLayer(organizationId: string): Promise<{ grants: EntitlementGrant[] | null; licenseId: string | null }> {
    const pub = this.config.licensePublicKey();
    if (!pub) return { grants: null, licenseId: null };
    const license = await (this.prisma as any).productLicense.findFirst({
      where: { OR: [{ organizationId }, { organizationId: null }] },
      orderBy: { installedAt: "desc" },
    });
    if (!license) return { grants: null, licenseId: null };
    const evaluation = evaluateLicense(
      { payload: { licenseId: license.licenseId, organization: license.organization, edition: license.edition, issuer: license.issuer, issuedAt: license.issuedAt.toISOString(), validFrom: license.validFrom.toISOString(), expiresAt: license.expiresAt.toISOString(), entitlements: license.entitlements, limits: license.limits }, signature: license.signature, algorithm: "Ed25519" },
      pub,
      { now: new Date(), graceDays: this.config.licenseGraceDays() },
    );
    if (!evaluation.capabilitiesActive) return { grants: null, licenseId: license.licenseId };
    const grants = (license.entitlements as any[]).map((e) => ({ featureKey: e.featureKey as FeatureKey, enabled: e.enabled, limit: e.limit ?? null }));
    return { grants, licenseId: license.licenseId };
  }

  async hasProductState(organizationId: string): Promise<boolean> {
    const [sub, trial, license] = await Promise.all([
      (this.prisma as any).subscription.findFirst({ where: { organizationId } }),
      (this.prisma as any).productTrial.findFirst({ where: { organizationId } }),
      (this.prisma as any).productLicense.findFirst({ where: { OR: [{ organizationId }, { organizationId: null }] } }),
    ]);
    return Boolean(sub || trial || license);
  }

  async getEffectiveEntitlements(organizationId: string): Promise<{ entitlements: EffectiveEntitlement[]; enforcementActive: boolean }> {
    const [subscription, trial, licenseLayer, overrides] = await Promise.all([
      (this.prisma as any).subscription.findFirst({
        where: { organizationId, status: { in: ["TRIALING", "ACTIVE", "PAST_DUE"] } },
        orderBy: { createdAt: "desc" },
      }),
      (this.prisma as any).productTrial.findFirst({
        where: { organizationId, status: "ACTIVE", expiresAt: { gt: new Date() } },
        orderBy: { createdAt: "desc" },
      }),
      this.licenseLayer(organizationId),
      (this.prisma as any).quotaOverride.findMany({ where: { organizationId } }),
    ]);

    const enforcementActive = Boolean(subscription || trial || licenseLayer.licenseId ||
      (await (this.prisma as any).productTrial.findFirst({ where: { organizationId } })) ||
      (await (this.prisma as any).subscription.findFirst({ where: { organizationId } })));

    const cacheKey = [
      subscription?.planVersionId ?? "nosub",
      trial?.id ?? "notrial",
      licenseLayer.licenseId ?? "nolicense",
      overrides.map((o: any) => `${o.id}:${o.newLimit}`).join(",") || "nooverride",
    ].join("|");
    const cached = this.cache.get(organizationId);
    if (cached && cached.key === cacheKey) return { entitlements: cached.value, enforcementActive: cached.enforcementActive };

    const planGrants = subscription ? await this.grantsForPlanVersion(subscription.planVersionId) : null;
    const trialGrants = !subscription && trial ? await this.grantsForPlanVersion(trial.planVersionId) : null;
    const limitOverrides = overrides
      .filter((o: any) => (!o.startsAt || o.startsAt <= new Date()) && (!o.expiresAt || o.expiresAt > new Date()))
      .map((o: any) => ({ featureKey: o.metric as FeatureKey, limit: o.newLimit }));

    const entitlements = computeEffectiveEntitlements({
      license: licenseLayer.grants,
      plan: planGrants,
      trial: trialGrants,
      limitOverrides,
    });
    this.cache.set(organizationId, { key: cacheKey, value: entitlements, enforcementActive });
    return { entitlements, enforcementActive };
  }

  async isEnabled(organizationId: string, featureKey: FeatureKey): Promise<boolean> {
    if (isSafetyInvariantKey(featureKey)) return true; // safety is not a feature (§16)
    const { entitlements, enforcementActive } = await this.getEffectiveEntitlements(organizationId);
    if (!enforcementActive) return true;
    return findEntitlement(entitlements, featureKey).enabled;
  }

  async getLimit(organizationId: string, featureKey: FeatureKey): Promise<number | null> {
    const { entitlements, enforcementActive } = await this.getEffectiveEntitlements(organizationId);
    if (!enforcementActive) return null;
    return findEntitlement(entitlements, featureKey).limit;
  }

  /** §12/§13: the backend gate. Fails closed for unentitled features. */
  async requireFeature(organizationId: string, featureKey: FeatureKey): Promise<void> {
    const enabled = await this.isEnabled(organizationId, featureKey);
    if (!enabled) {
      throw new ForbiddenException({
        error: "FEATURE_NOT_ENTITLED",
        feature: featureKey,
        message: `Feature ${featureKey} is not entitled for this organization. Safety controls are unaffected by entitlements (§16).`,
      });
    }
  }
}
