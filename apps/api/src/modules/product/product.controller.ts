import { Body, Controller, Get, Headers, Param, Post, Query, Req } from "@nestjs/common";
import type { Request } from "express";
import { CurrentUser, Public, type RequestUser } from "../../common/decorators/auth.decorators";
import { clientIp } from "../../common/middleware/request-id.middleware";
import { parseOrThrow } from "../../common/parse";
import { PlansService } from "./plans/plans.service";
import { ProductConfigService } from "./product-config.service";
import { ProductPermissionService } from "./permissions";
import { EntitlementService } from "./entitlements/entitlement.service";
import { UsageMeteringService } from "./usage/usage.service";
import { QuotaEnforcementService } from "./quotas/quota.service";
import { SubscriptionService } from "./subscriptions/subscription.service";
import { BillingService } from "./billing/billing.service";
import { LicenseService } from "./licenses/license.service";
import { TrialService } from "./trials/trial.service";
import { CustomerProvisioningService } from "./provisioning/provisioning.service";
import { OnboardingService } from "./onboarding/onboarding.service";
import { OrganizationLifecycleService } from "./lifecycle/lifecycle.service";
import { EffectiveCapabilityService } from "./capabilities/capability.service";
import { SupportDiagnosticsService } from "./diagnostics/diagnostics.service";
import { UpgradePreflightService } from "./upgrade/upgrade-preflight.service";
import {
  cancelSubscriptionSchema, changePlanSchema, completeStepSchema, deletionRequestSchema,
  installLicenseSchema, signupSchema, verifyEmailSchema,
} from "./dto/product.dto";
import { QUOTA_DIMENSIONS } from "@zerosweep/security-sdk";

/**
 * Tenant-facing product API (Prompt 40). Every route is scoped to the
 * caller's own organization from the JWT — there is no organizationId
 * parameter a tenant could manipulate (§133/§134/§140). Feature access
 * is enforced in services, not by hiding UI (§12).
 */
@Controller("product")
export class ProductController {
  constructor(
    private readonly plans: PlansService,
    private readonly config: ProductConfigService,
    private readonly permissions: ProductPermissionService,
    private readonly entitlements: EntitlementService,
    private readonly usage: UsageMeteringService,
    private readonly quotas: QuotaEnforcementService,
    private readonly subscriptions: SubscriptionService,
    private readonly billing: BillingService,
    private readonly licenses: LicenseService,
    private readonly trials: TrialService,
    private readonly provisioning: CustomerProvisioningService,
    private readonly onboarding: OnboardingService,
    private readonly lifecycle: OrganizationLifecycleService,
    private readonly capabilities: EffectiveCapabilityService,
    private readonly diagnostics: SupportDiagnosticsService,
    private readonly upgradePreflight: UpgradePreflightService,
  ) {}

  // ---- Signup / provisioning (§58–§64) -------------------------------------

  @Public()
  @Post("signup")
  signup(@Body() body: unknown, @Req() req: Request) {
    return this.provisioning.signup(parseOrThrow(signupSchema, body), clientIp(req));
  }

  @Public()
  @Post("verify-email")
  verifyEmail(@Body() body: unknown) {
    const data = parseOrThrow(verifyEmailSchema, body);
    return this.provisioning.verifyEmail(data.token);
  }

  // ---- Billing webhook (§23) ------------------------------------------------

  @Public()
  @Post("billing/webhook/:provider")
  async webhook(
    @Param("provider") provider: string,
    @Req() req: { rawBody?: string; body?: unknown },
    @Headers("x-billing-signature") signature?: string,
    @Headers("x-billing-timestamp") timestamp?: string,
  ) {
    const rawBody = req.rawBody ?? JSON.stringify(req.body ?? {});
    return this.billing.handleWebhook({ provider, rawBody, signature: signature ?? null, timestamp: timestamp ?? null });
  }

  // ---- Own product state (§106–§112) ----------------------------------------

  @Get("me")
  async me(@CurrentUser() user: RequestUser) {
    const [effective, subscription, trial, license] = await Promise.all([
      this.entitlements.getEffectiveEntitlements(user.organizationId),
      this.subscriptions.getForOrganization(user.organizationId),
      this.trials.getForOrganization(user.organizationId),
      this.licenses.getCurrent(user.organizationId),
    ]);
    return {
      productMode: this.config.productMode(),
      releaseVersion: this.config.releaseVersion(),
      enforcementActive: effective.enforcementActive,
      entitlements: effective.entitlements,
      subscription: subscription
        ? { id: subscription.id, status: subscription.status, planVersionId: subscription.planVersionId, planCode: subscription.planVersion?.plan?.code ?? null, currentPeriodStart: subscription.currentPeriodStart, currentPeriodEnd: subscription.currentPeriodEnd, cancelAtPeriodEnd: subscription.cancelAtPeriodEnd }
        : null,
      trial: trial ? { id: trial.id, status: trial.status, expiresAt: trial.expiresAt } : null,
      license: { installed: license.installed, licensingEnabled: license.licensingEnabled, status: license.evaluation?.status ?? null, edition: license.license?.edition ?? null, expiresAt: license.license?.expiresAt ?? null },
      billing: this.billing.status(),
    };
  }

  @Get("usage")
  async usageView(@CurrentUser() user: RequestUser, @Query("days") daysRaw?: string) {
    this.permissions.requireBillingPermission(user, "VIEW_USAGE");
    const days = Math.min(Math.max(Number(daysRaw ?? 30) || 30, 1), 366);
    const to = new Date();
    const from = new Date(to.getTime() - days * 86_400_000);
    const [usage, quotaStatus] = await Promise.all([
      this.usage.getUsage(user.organizationId, from, to),
      Promise.all(QUOTA_DIMENSIONS.map(async (dimension) => {
        const [{ limit, source }, currentUsage] = await Promise.all([
          this.quotas.getLimit(user.organizationId, dimension),
          this.quotas.getCurrentUsage(user.organizationId, dimension),
        ]);
        return { dimension, currentUsage, limit, source, overLimit: limit !== null && currentUsage > limit };
      })),
    ]);
    const subscription = await this.subscriptions.getForOrganization(user.organizationId);
    return {
      plan: subscription ? { planVersionId: subscription.planVersionId, status: subscription.status, periodStart: subscription.currentPeriodStart, periodEnd: subscription.currentPeriodEnd } : null,
      usage, quotas: quotaStatus, period: { from, to },
    };
  }

  /** Plan catalog (§107): ACTIVE plans with versions + entitlements. */
  @Get("plans")
  async plansCatalog() {
    const plans = await this.plans.listPlans();
    return { items: plans.filter((p) => p.status === "ACTIVE") };
  }

  @Get("capabilities")
  capabilitiesView(@CurrentUser() user: RequestUser) {
    return this.capabilities.resolveForOrganization(user.organizationId, user.role);
  }

  @Get("commercial-tools")
  commercialTools() {
    return this.capabilities.commercialToolStatuses();
  }

  // ---- Onboarding (§65–§75) ---------------------------------------------------

  @Get("onboarding")
  onboardingState(@CurrentUser() user: RequestUser) {
    return this.onboarding.getState(user.organizationId);
  }

  @Post("onboarding/steps/:step/complete")
  completeStep(@CurrentUser() user: RequestUser, @Param("step") step: string, @Body() body: unknown) {
    const data = parseOrThrow(completeStepSchema, body ?? {}) ?? {};
    return this.onboarding.completeStep(user, step, data);
  }

  @Post("onboarding/steps/:step/skip")
  skipStep(@CurrentUser() user: RequestUser, @Param("step") step: string) {
    return this.onboarding.skipStep(user, step);
  }

  // ---- Subscription management (§113–§118) -------------------------------------

  @Post("subscription/upgrade")
  async upgrade(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    this.permissions.requireBillingPermission(user, "MANAGE_PLAN");
    const data = parseOrThrow(changePlanSchema, body);
    const result = await this.subscriptions.upgrade(user.id, user.organizationId, data.planVersionId);
    await this.trials.markConverted(user.organizationId);
    return result;
  }

  @Post("subscription/downgrade/preview")
  async downgradePreview(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    this.permissions.requireBillingPermission(user, "MANAGE_PLAN");
    const data = parseOrThrow(changePlanSchema, body);
    return this.subscriptions.previewDowngrade(user.organizationId, data.planVersionId);
  }

  @Post("subscription/downgrade")
  downgrade(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    this.permissions.requireBillingPermission(user, "MANAGE_PLAN");
    const data = parseOrThrow(changePlanSchema, body);
    return this.subscriptions.downgrade(user.id, user.organizationId, data.planVersionId, data.impactAcknowledged === true);
  }

  @Post("subscription/cancel")
  cancel(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    this.permissions.requireBillingPermission(user, "MANAGE_PLAN");
    const data = parseOrThrow(cancelSubscriptionSchema, body ?? {});
    return this.subscriptions.cancel(user.id, user.organizationId, data.atPeriodEnd ?? true);
  }

  // ---- License (§110–§112) ------------------------------------------------------

  @Get("license")
  license(@CurrentUser() user: RequestUser) {
    return this.licenses.getCurrent(user.organizationId);
  }

  @Post("license/install")
  installLicense(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    this.permissions.requireBillingPermission(user, "MANAGE_LICENSE");
    const data = parseOrThrow(installLicenseSchema, body);
    return this.licenses.install(user, data.document);
  }

  // ---- Billing views (§109/§134) --------------------------------------------------

  @Get("billing")
  async billingView(@CurrentUser() user: RequestUser) {
    this.permissions.requireBillingPermission(user, "VIEW_BILLING");
    const [events, invoices] = await Promise.all([
      this.billing.listEvents(user.organizationId),
      this.billing.listInvoices(user.organizationId),
    ]);
    return { status: this.billing.status(), events, invoices };
  }

  // ---- Metering (§38) ------------------------------------------------------------
  // There is deliberately NO tenant route for recording usage: the
  // UsageEvent ledger is authoritative for quota/billing, so writes are
  // service-only (internal callers such as ProductGateService.recordScanUsage
  // invoke UsageMeteringService directly). Tenants may only READ their own
  // usage via GET /product/usage (VIEW_USAGE).

  // ---- Organization lifecycle (§86–§93) ----------------------------------------------

  @Post("organization/cancel")
  async cancelOrganization(@CurrentUser() user: RequestUser) {
    this.permissions.requireBillingPermission(user, "MANAGE_PLAN");
    await this.subscriptions.cancel(user.id, user.organizationId, true).catch(() => undefined);
    return this.lifecycle.requestCancellation(user.id, user.organizationId);
  }

  @Post("organization/deletion/preview")
  deletionPreview(@CurrentUser() user: RequestUser) {
    this.permissions.requireBillingPermission(user, "MANAGE_PLAN");
    return this.lifecycle.deletionPreview(user.organizationId);
  }

  @Post("organization/deletion/request")
  requestDeletion(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    this.permissions.requireBillingPermission(user, "MANAGE_PLAN");
    const data = parseOrThrow(deletionRequestSchema, body);
    return this.lifecycle.requestDeletion(user.id, user.organizationId, data.typedConfirmation);
  }

  // ---- Diagnostics & upgrade (§206–§210, §190) -------------------------------------------

  @Get("diagnostics")
  async diagnosticsBundle(@CurrentUser() user: RequestUser) {
    this.permissions.requireBillingPermission(user, "MANAGE_LICENSE");
    return this.diagnostics.generateBundle();
  }

  @Get("health")
  health() {
    return this.diagnostics.productHealthCheck();
  }

  @Get("upgrade/preflight")
  preflight(@CurrentUser() user: RequestUser, @Query("target") target?: string) {
    // Operator planning data (backup posture, worker compatibility) —
    // gated exactly like the diagnostics sibling: MANAGE_LICENSE
    // (OWNER/ADMIN), never any authenticated tenant user.
    this.permissions.requireBillingPermission(user, "MANAGE_LICENSE");
    return this.upgradePreflight.preflight(target ?? "1.0.0");
  }
}
