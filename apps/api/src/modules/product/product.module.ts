import { Module } from "@nestjs/common";
import { AuditModule } from "../audit/audit.module";
import { HealthModule } from "../../health/health.module";
import { PlatformOpsModule } from "../platform-ops/platform-ops.module";
import { ProductController } from "./product.controller";
import { ProductConfigService } from "./product-config.service";
import { ProductPermissionService } from "./permissions";
import { PlansService } from "./plans/plans.service";
import { EntitlementService } from "./entitlements/entitlement.service";
import { ProductGateService } from "./entitlements/product-gate.service";
import { SubscriptionService } from "./subscriptions/subscription.service";
import { BillingService } from "./billing/billing.service";
import { LicenseService } from "./licenses/license.service";
import { UsageMeteringService } from "./usage/usage.service";
import { QuotaEnforcementService } from "./quotas/quota.service";
import { TrialService } from "./trials/trial.service";
import { CustomerProvisioningService } from "./provisioning/provisioning.service";
import { OnboardingService } from "./onboarding/onboarding.service";
import { OrganizationLifecycleService } from "./lifecycle/lifecycle.service";
import { EffectiveCapabilityService } from "./capabilities/capability.service";
import { AbusePreventionService } from "./abuse/abuse.service";
import { ProductAnalyticsService } from "./analytics/analytics.service";
import { SupportDiagnosticsService } from "./diagnostics/diagnostics.service";
import { UpgradePreflightService } from "./upgrade/upgrade-preflight.service";

/**
 * Prompt 40 productization module (§2): plans, entitlements,
 * subscriptions, licenses, usage, quotas, trials, provisioning,
 * onboarding, billing, lifecycle, capabilities, abuse prevention,
 * analytics, diagnostics and upgrade preflight — one module, one
 * codebase for every product mode (§5).
 *
 * ProductGateService is exported so the scan-start path
 * (OrchestrationModule) shares the same gate instance (§12).
 */
@Module({
  imports: [AuditModule, HealthModule, PlatformOpsModule],
  controllers: [ProductController],
  providers: [
    ProductConfigService, ProductPermissionService, PlansService, EntitlementService,
    // (PlansService is also a controller dependency for the plan catalog.)
    ProductGateService, SubscriptionService, BillingService, LicenseService,
    UsageMeteringService, QuotaEnforcementService, TrialService,
    CustomerProvisioningService, OnboardingService, OrganizationLifecycleService,
    EffectiveCapabilityService, AbusePreventionService, ProductAnalyticsService,
    SupportDiagnosticsService, UpgradePreflightService,
  ],
  exports: [
    ProductConfigService, ProductPermissionService, PlansService, EntitlementService,
    ProductGateService, SubscriptionService, BillingService, LicenseService,
    UsageMeteringService, QuotaEnforcementService, TrialService,
    CustomerProvisioningService, OnboardingService, OrganizationLifecycleService,
    EffectiveCapabilityService, AbusePreventionService, ProductAnalyticsService,
    SupportDiagnosticsService, UpgradePreflightService,
  ],
})
export class ProductModule {}
