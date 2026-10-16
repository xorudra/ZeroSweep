import { Body, Controller, Get, Param, Post, Query } from "@nestjs/common";
import { CurrentUser, type RequestUser } from "../../common/decorators/auth.decorators";
import { parseOrThrow } from "../../common/parse";
import { PRODUCT_FEATURE_REGISTRY } from "@dsrclone/security-sdk";
import { ProductPermissionService } from "../product/permissions";
import { PlansService } from "../product/plans/plans.service";
import { SubscriptionService } from "../product/subscriptions/subscription.service";
import { TrialService } from "../product/trials/trial.service";
import { QuotaEnforcementService } from "../product/quotas/quota.service";
import { OrganizationLifecycleService } from "../product/lifecycle/lifecycle.service";
import { BillingService } from "../product/billing/billing.service";
import { ProductAnalyticsService } from "../product/analytics/analytics.service";
import { ProductConfigService } from "../product/product-config.service";
import { PlatformControlDataService } from "./platform-control.service";
import {
  createPlanSchema, createSubscriptionSchema, legalHoldSchema, manualInvoiceSchema,
  planStatusSchema, quotaOverrideSchema, supportAccessCreateSchema, updatePlanSchema,
} from "../product/dto/product.dto";

/**
 * Platform control plane (Prompt 40 §95–§98). Routes live under
 * /platform/* alongside the Prompt 38 operations surface, but every
 * product route additionally requires the deployment-level platform
 * administrator flag (§98) and the §136 platform permissions. Tenant
 * organization roles never suffice. All views are metadata-only
 * (§104–§106): no passwords, no secrets, no customer content.
 */
@Controller("platform")
export class PlatformControlController {
  constructor(
    private readonly permissions: ProductPermissionService,
    private readonly data: PlatformControlDataService,
    private readonly plans: PlansService,
    private readonly subscriptionSvc: SubscriptionService,
    private readonly trialSvc: TrialService,
    private readonly quotas: QuotaEnforcementService,
    private readonly lifecycle: OrganizationLifecycleService,
    private readonly billing: BillingService,
    private readonly analytics: ProductAnalyticsService,
    private readonly config: ProductConfigService,
  ) {}

  @Get("organizations")
  async organizations(@CurrentUser() user: RequestUser) {
    await this.permissions.requirePlatformPermission(user, "VIEW_PLATFORM_ORGANIZATIONS");
    return { items: await this.data.listOrganizations() };
  }

  @Get("organizations/:id")
  async organization(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    await this.permissions.requirePlatformPermission(user, "VIEW_PLATFORM_ORGANIZATIONS");
    return this.data.getOrganization(id);
  }

  @Post("organizations/:id/suspend")
  async suspend(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    await this.permissions.requirePlatformPermission(user, "MANAGE_PLATFORM_ORGANIZATIONS");
    return this.lifecycle.suspend(user.id, id);
  }

  @Post("organizations/:id/reactivate")
  async reactivate(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    await this.permissions.requirePlatformPermission(user, "MANAGE_PLATFORM_ORGANIZATIONS");
    return this.lifecycle.reactivate(user.id, id);
  }

  @Post("organizations/:id/legal-hold")
  async legalHold(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    await this.permissions.requirePlatformPermission(user, "MANAGE_PLATFORM_ORGANIZATIONS");
    const data = parseOrThrow(legalHoldSchema, body);
    return this.lifecycle.setLegalHold(user.id, id, data.hold);
  }

  @Get("subscriptions")
  async subscriptions(@CurrentUser() user: RequestUser) {
    await this.permissions.requirePlatformPermission(user, "VIEW_PLATFORM_SUBSCRIPTIONS");
    return { items: await this.data.listSubscriptions() };
  }

  @Post("subscriptions")
  async createSubscription(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    await this.permissions.requirePlatformPermission(user, "MANAGE_PLATFORM_SUBSCRIPTIONS");
    const data = parseOrThrow(createSubscriptionSchema, body);
    return this.subscriptionSvc.create(user.id, data);
  }

  @Get("licenses")
  async licenses(@CurrentUser() user: RequestUser) {
    await this.permissions.requirePlatformPermission(user, "MANAGE_PLATFORM_LICENSES");
    return { items: await this.data.listLicenses() };
  }

  @Get("usage")
  async usage(@CurrentUser() user: RequestUser) {
    await this.permissions.requirePlatformPermission(user, "VIEW_PLATFORM_USAGE");
    return { items: await this.data.usageTotals() };
  }

  @Get("trials")
  async trials(@CurrentUser() user: RequestUser) {
    await this.permissions.requirePlatformPermission(user, "VIEW_PLATFORM_SUBSCRIPTIONS");
    return { items: await this.data.listTrials() };
  }

  @Post("trials/expire")
  async expireTrials(@CurrentUser() user: RequestUser) {
    await this.permissions.requirePlatformPermission(user, "MANAGE_PLATFORM_SUBSCRIPTIONS");
    return { expired: await this.trialSvc.expireTrials() };
  }

  @Get("features")
  async features(@CurrentUser() user: RequestUser) {
    await this.permissions.requirePlatformPermission(user, "MANAGE_PRODUCT_FEATURES");
    return { items: PRODUCT_FEATURE_REGISTRY };
  }

  @Get("plans")
  async listPlans(@CurrentUser() user: RequestUser) {
    await this.permissions.requirePlatformPermission(user, "MANAGE_PRODUCT_PLANS");
    return { items: await this.plans.listPlans() };
  }

  @Post("plans")
  async createPlan(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    await this.permissions.requirePlatformPermission(user, "MANAGE_PRODUCT_PLANS");
    const data = parseOrThrow(createPlanSchema, body);
    return this.plans.createPlan(user.id, data);
  }

  @Post("plans/:id")
  async updatePlan(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    await this.permissions.requirePlatformPermission(user, "MANAGE_PRODUCT_PLANS");
    const data = parseOrThrow(updatePlanSchema, body);
    return this.plans.updatePlan(user.id, id, data);
  }

  @Post("plans/:id/status")
  async planStatus(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    await this.permissions.requirePlatformPermission(user, "MANAGE_PRODUCT_PLANS");
    const data = parseOrThrow(planStatusSchema, body);
    return this.plans.setPlanStatus(user.id, id, data.status);
  }

  @Post("quota-overrides")
  async quotaOverride(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    await this.permissions.requirePlatformPermission(user, "MANAGE_PLATFORM_SUBSCRIPTIONS");
    const data = parseOrThrow(quotaOverrideSchema, body);
    return this.quotas.createOverride({ id: user.id }, {
      organizationId: data.organizationId, metric: data.metric, newLimit: data.newLimit,
      reason: data.reason, expiresAt: data.expiresAt ? new Date(data.expiresAt) : null,
    });
  }

  @Post("billing/manual-invoices")
  async manualInvoice(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    await this.permissions.requirePlatformPermission(user, "MANAGE_PLATFORM_SUBSCRIPTIONS");
    const data = parseOrThrow(manualInvoiceSchema, body);
    return this.billing.recordManualInvoice(user.id, data);
  }

  @Get("release")
  async release(@CurrentUser() user: RequestUser) {
    await this.permissions.requirePlatformPermission(user, "VIEW_PLATFORM_ORGANIZATIONS");
    return {
      version: this.config.releaseVersion(),
      productMode: this.config.productMode(),
      billing: this.billing.status(),
      licensingEnabled: this.config.licensingEnabled(),
      analyticsEventCounts: await this.analytics.aggregateCounts(),
    };
  }

  @Get("audit")
  async audit(@CurrentUser() user: RequestUser, @Query("organizationId") organizationId: string) {
    await this.permissions.requirePlatformPermission(user, "VIEW_PLATFORM_ORGANIZATIONS");
    return { items: await this.data.supportAuditTrail(organizationId) };
  }

  // ---- Support access (§100–§103) ------------------------------------------

  @Get("support-access")
  async supportSessions(@CurrentUser() user: RequestUser, @Query("organizationId") organizationId?: string) {
    await this.permissions.requirePlatformPermission(user, "MANAGE_SUPPORT_ACCESS");
    return { items: await this.data.listSupportSessions(organizationId) };
  }

  @Post("support-access")
  async createSupportSession(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    await this.permissions.requirePlatformPermission(user, "MANAGE_SUPPORT_ACCESS");
    const data = parseOrThrow(supportAccessCreateSchema, body);
    // tenantApproved is deliberately NOT forwarded: approval is a
    // separate tenant-side action (see the approve route below), never
    // a field the operator attests in their own create request.
    const { tenantApproved: _ignored, ...rest } = data as typeof data & { tenantApproved?: boolean };
    return this.data.createSupportSession(user, { ...rest, expiresInHours: data.expiresInHours ?? 8 });
  }

  /** Tenant-side approval (§100–§103): only a member of the target
   *  tenant can approve — the session is looked up under the CALLER's
   *  own organization, so a session belonging to another tenant is
   *  simply not found. No platform permission is required or sufficient;
   *  the approver is recorded as approvedById by the service. */
  @Post("support-access/:id/approve")
  async approveSupportSession(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    return this.data.approveSupportSession(user.organizationId, id, user.id);
  }

  @Post("support-access/:id/end")
  async endSupportSession(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    await this.permissions.requirePlatformPermission(user, "MANAGE_SUPPORT_ACCESS");
    return this.data.endSupportSession(user.id, id);
  }
}
