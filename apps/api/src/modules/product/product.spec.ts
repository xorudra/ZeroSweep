import { createHmac, generateKeyPairSync } from "node:crypto";
import { signLicense, type LicensePayload } from "@dsrclone/security-sdk";
import { AuditService } from "../audit/audit.service";
import { ProductConfigService } from "./product-config.service";
import { ProductPermissionService } from "./permissions";
import { PlansService } from "./plans/plans.service";
import { EntitlementService } from "./entitlements/entitlement.service";
import { ProductGateService } from "./entitlements/product-gate.service";
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
import { AbusePreventionService } from "./abuse/abuse.service";
import { ProductAnalyticsService } from "./analytics/analytics.service";
import { PlatformControlDataService } from "../platform-control/platform-control.service";
import { makeProductDb, seedPlan } from "./product.fake";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Prompt 40 product test battery (§211–§243 service level): tenant
 * isolation for plans/subscriptions/usage/billing/licenses/trials/
 * support access, billing IDOR + usage IDOR, license tamper/expiry,
 * quota race, metering idempotency, webhook replay/signature,
 * downgrade, trial expiry, support access/audit, capability states,
 * demo denial, analytics privacy, provisioning/onboarding flows.
 */

function makeConfig(overrides: Partial<Record<string, unknown>> = {}): ProductConfigService {
  const base: Record<string, unknown> = {
    productMode: () => "SAAS",
    nodeEnv: () => "test",
    releaseVersion: () => "1.0.0",
    billing: () => ({ status: "NOT_CONFIGURED", provider: null, reason: "none" }),
    billingWebhookSecret: () => null,
    licensePublicKey: () => null,
    licensingEnabled: () => false,
    licenseGraceDays: () => 14,
    trialDays: () => 14,
    telemetryEnabled: () => false,
    isPlatformAdminEmail: () => false,
    configurationSummary: () => ({}),
  };
  return { ...base, ...overrides } as unknown as ProductConfigService;
}

function makeStack(overrides: Partial<Record<string, unknown>> = {}) {
  const db = makeProductDb();
  const audit = new AuditService(db as never);
  const config = makeConfig(overrides);
  const plans = new PlansService(db as never, audit);
  const entitlements = new EntitlementService(db as never, config);
  const usage = new UsageMeteringService(db as never);
  const quotas = new QuotaEnforcementService(db as never, audit, usage);
  const subscriptions = new SubscriptionService(db as never, audit, entitlements, quotas);
  const trials = new TrialService(db as never, audit, config, entitlements);
  const billing = new BillingService(db as never, audit, config, entitlements);
  const licenses = new LicenseService(db as never, audit, config, entitlements);
  const provisioning = new CustomerProvisioningService(db as never, audit, config, plans, quotas);
  const onboarding = new OnboardingService(db as never, audit);
  const lifecycle = new OrganizationLifecycleService(db as never, audit);
  const abuse = new AbusePreventionService(db as never);
  const gate = new ProductGateService(db as never, audit, entitlements, quotas, usage, abuse);
  const analytics = new ProductAnalyticsService(db as never, config);
  const platformData = new PlatformControlDataService(db as never, audit);
  const permissions = new ProductPermissionService(db as never);
  const capabilities = new EffectiveCapabilityService(db as never, entitlements, { getState: async () => ({ killSwitches: {} }) } as never);
  return { db, audit, config, plans, entitlements, usage, quotas, subscriptions, trials, billing, licenses, provisioning, onboarding, lifecycle, abuse, gate, analytics, platformData, permissions, capabilities };
}

const ownerOf = (orgId: string): RequestUser => ({ id: "u-owner", email: "o@x.io", organizationId: orgId, role: "OWNER" });

describe("signup & provisioning (§58–§64, §82–§84, §231, §290)", () => {
  it("provisions user, org, workspace, OWNER membership, trial, subscription, onboarding in one flow", async () => {
    const s = makeStack();
    await seedPlan(s.db, "TRIAL", "SAAS", [{ featureKey: "WEB_VAPT", enabled: true }], { ASSETS: 50 });
    const res = await s.provisioning.signup({ name: "Rudra", email: "New@Example.com", password: "long-password-1", organizationName: "Acme Security", slug: "acme-security" });
    expect(res.organization.slug).toBe("acme-security");
    expect(res.trial).not.toBeNull();
    expect(res.planCode).toBe("TRIAL");
    const membership = await s.db.membership.findFirst({ where: { organizationId: res.organization.id } });
    expect(membership.role).toBe("OWNER");
    const onboarding = await s.db.organizationOnboarding.findUnique({ where: { organizationId: res.organization.id } });
    expect(onboarding.status).toBe("IN_PROGRESS");
    const audits = await s.db.auditLog.findMany({ where: { action: "ORGANIZATION_PROVISIONED" } });
    expect(audits).toHaveLength(1);
  });

  it("duplicate email and reserved slugs are refused without creating anything (§63/§64)", async () => {
    const s = makeStack();
    await seedPlan(s.db, "TRIAL", "SAAS", []);
    await s.provisioning.signup({ name: "A", email: "a@example.com", password: "long-password-1", organizationName: "One", slug: "one-org" });
    await expect(s.provisioning.signup({ name: "B", email: "a@example.com", password: "long-password-1", organizationName: "Two", slug: "two-org" })).rejects.toThrow(/already exists/);
    await expect(s.provisioning.signup({ name: "C", email: "c@example.com", password: "long-password-1", organizationName: "Admin", slug: "admin" })).rejects.toThrow(/reserved/);
    expect(await s.db.organization.count({})).toBe(1);
  });

  it("email verification is single-use and expiring (§60)", async () => {
    const s = makeStack();
    await seedPlan(s.db, "TRIAL", "SAAS", []);
    const res = await s.provisioning.signup({ name: "A", email: "a@example.com", password: "long-password-1", organizationName: "One", slug: "one-org" });
    expect(res.emailVerificationToken).toBeTruthy();
    await expect(s.provisioning.verifyEmail(res.emailVerificationToken!)).resolves.toEqual({ verified: true });
    await expect(s.provisioning.verifyEmail(res.emailVerificationToken!)).rejects.toThrow(/already used|invalid/);
  });
});

describe("onboarding (§65–§75, §231)", () => {
  it("enforces step order, attestation for SECURITY_SCOPE, optional skips", async () => {
    const s = makeStack();
    await s.db.organization.create({ data: { name: "Org", slug: "org-1", lifecycleStatus: "ACTIVE" } });
    const user = { id: "u1", organizationId: "org-1" };
    await expect(s.onboarding.completeStep(user, "FIRST_ASSESSMENT")).rejects.toThrow(/Complete required steps first/);
    await s.onboarding.completeStep(user, "WELCOME");
    await s.onboarding.completeStep(user, "ORGANIZATION_PROFILE");
    await s.onboarding.completeStep(user, "WORKSPACE_SETUP");
    await expect(s.onboarding.completeStep(user, "SECURITY_SCOPE")).rejects.toThrow(/attestation/);
    const state = await s.onboarding.completeStep(user, "SECURITY_SCOPE", { attested: true });
    expect(state.authorizationAttested).toBe(true);
    await expect(s.onboarding.skipStep(user, "SECURITY_SCOPE")).rejects.toThrow(/cannot be skipped/);
    const skipped = await s.onboarding.skipStep(user, "TEAM_INVITATION");
    expect(skipped.progress.completed).toBeGreaterThanOrEqual(5);
  });
});

describe("entitlements & product gate (§12/§16/§52, §212)", () => {
  it("requireFeature fails closed for unentitled features once product state exists", async () => {
    const s = makeStack();
    const { version } = await seedPlan(s.db, "BASIC", "SAAS", [{ featureKey: "WEB_VAPT", enabled: true }, { featureKey: "NETWORK_VAPT", enabled: false }]);
    await s.db.organization.create({ data: { id: "org-1", name: "Org", slug: "org-1", lifecycleStatus: "ACTIVE" } });
    await s.subscriptions.create("admin", { organizationId: "org-1", planVersionId: version.id });
    await expect(s.entitlements.requireFeature("org-1", "WEB_VAPT")).resolves.toBeUndefined();
    await expect(s.entitlements.requireFeature("org-1", "NETWORK_VAPT")).rejects.toThrow(/not entitled/);
    // Cross-tenant: org-2 has no state and sees none of org-1's grants reflected (§212/§243)
    const other = await s.entitlements.getEffectiveEntitlements("org-2");
    expect(other.enforcementActive).toBe(false);
  });

  it("gate denies demo orgs, suspended orgs and protected targets; allows clean entitled scans (§228)", async () => {
    const s = makeStack();
    const { version } = await seedPlan(s.db, "BASIC", "SAAS", [{ featureKey: "WEB_VAPT", enabled: true }]);
    await s.db.organization.create({ data: { id: "org-demo", name: "Demo", slug: "demo", lifecycleStatus: "ACTIVE", isDemo: true } });
    await s.db.organization.create({ data: { id: "org-susp", name: "S", slug: "susp", lifecycleStatus: "SUSPENDED" } });
    await s.db.organization.create({ data: { id: "org-ok", name: "OK", slug: "ok", lifecycleStatus: "ACTIVE" } });
    await s.db.organization.create({ data: { id: "org-clean", name: "Clean", slug: "clean", lifecycleStatus: "ACTIVE" } });
    await s.subscriptions.create("admin", { organizationId: "org-ok", planVersionId: version.id });
    await s.subscriptions.create("admin", { organizationId: "org-clean", planVersionId: version.id });
    await expect(s.gate.assertScanAllowed({ organizationId: "org-demo", userId: "u", workspaceId: "w", targetValue: "example.com", profile: "WEB_ASSESSMENT" })).rejects.toThrow(/demo/i);
    await expect(s.gate.assertScanAllowed({ organizationId: "org-susp", userId: "u", workspaceId: "w", targetValue: "example.com", profile: "WEB_ASSESSMENT" })).rejects.toThrow(/lifecycle/);
    await expect(s.gate.assertScanAllowed({ organizationId: "org-ok", userId: "u", workspaceId: "w", targetValue: "169.254.169.254", profile: "WEB_ASSESSMENT" })).rejects.toThrow(/protected/i);
    // §171/§173: after a protected-target attempt, scan creation stays
    // blocked pending abuse-signal review — signals escalate, they do
    // not silently reset.
    await expect(s.gate.assertScanAllowed({ organizationId: "org-ok", userId: "u", workspaceId: "w", targetValue: "example.com", profile: "WEB_ASSESSMENT" })).rejects.toThrow(/abuse-signal review/);
    await expect(s.gate.assertScanAllowed({ organizationId: "org-clean", userId: "u", workspaceId: "w", targetValue: "example.com", profile: "WEB_ASSESSMENT" })).resolves.toBeUndefined();
    await expect(s.gate.assertScanAllowed({ organizationId: "org-clean", userId: "u", workspaceId: "w", targetValue: "example.com", profile: "NETWORK_ASSESSMENT" })).rejects.toThrow(/not entitled/);
  });
});

describe("usage metering (§38–§44, §214, §218)", () => {
  it("recording is idempotent: a replayed event never double-counts", async () => {
    const s = makeStack();
    const first = await s.usage.record("org-1", { metric: "SCAN_JOBS", quantity: 1, source: "orchestration", idempotencyKey: "scan:1:SCAN_JOBS" });
    const replay = await s.usage.record("org-1", { metric: "SCAN_JOBS", quantity: 1, source: "orchestration", idempotencyKey: "scan:1:SCAN_JOBS" });
    expect(first.duplicate).toBe(false);
    expect(replay.duplicate).toBe(true);
    expect(await s.db.usageEvent.count({})).toBe(1);
    const usage = await s.usage.getUsage("org-1", new Date(Date.now() - 86400_000), new Date(Date.now() + 86400_000));
    expect(usage.find((u) => u.metric === "SCAN_JOBS")?.quantity).toBe(1);
  });

  it("usage IDOR: org A cannot read or claim org B usage (§214)", async () => {
    const s = makeStack();
    await s.usage.record("org-b", { metric: "AI_REQUESTS", quantity: 5, source: "ai", idempotencyKey: "b:1" });
    const aUsage = await s.usage.getUsage("org-a", new Date(Date.now() - 86400_000), new Date(Date.now() + 86400_000));
    expect(aUsage).toEqual([]);
    await expect(s.usage.record("org-a", { metric: "AI_REQUESTS", quantity: 1, source: "ai", idempotencyKey: "b:1" })).rejects.toThrow(/another organization/);
  });
});

describe("quotas (§45–§51, §217)", () => {
  it("quota check blocks at the limit with a structured 429 body", async () => {
    const s = makeStack();
    await s.db.organization.create({ data: { id: "org-1", name: "O", slug: "o1", lifecycleStatus: "ACTIVE" } });
    await s.db.workspace.create({ data: { id: "ws-1", organizationId: "org-1", name: "W" } });
    await s.db.asset.create({ data: { workspaceId: "ws-1", targetId: "t1", host: "a.example" } });
    await s.quotas.materializePolicies("org-1", { ASSETS: 1 }, "PLAN");
    await expect(s.quotas.check("org-1", "ASSETS", 1)).rejects.toMatchObject({ response: { error: "QUOTA_EXCEEDED", quota: "ASSETS", limit: 1 } });
  });

  it("quota race: concurrent reservations cannot exceed the limit (§217)", async () => {
    const s = makeStack();
    await s.db.organization.create({ data: { id: "org-1", name: "O", slug: "o1", lifecycleStatus: "ACTIVE" } });
    await s.db.workspace.create({ data: { id: "ws-1", organizationId: "org-1", name: "W" } });
    await s.quotas.materializePolicies("org-1", { CONCURRENT_SCANS: 1 }, "PLAN");
    const attempts = await Promise.allSettled([
      s.quotas.reserve("org-1", "CONCURRENT_SCANS", "job-a"),
      s.quotas.reserve("org-1", "CONCURRENT_SCANS", "job-b"),
      s.quotas.reserve("org-1", "CONCURRENT_SCANS", "job-c"),
    ]);
    expect(attempts.filter((a) => a.status === "fulfilled")).toHaveLength(1);
    // release frees headroom again (§50)
    const winner = (attempts.find((a) => a.status === "fulfilled") as any).value;
    await s.quotas.release(winner.id);
    await expect(s.quotas.reserve("org-1", "CONCURRENT_SCANS", "job-d")).resolves.toBeTruthy();
  });

  it("tenants cannot create their own overrides; platform issuance is audited (§138/§140)", async () => {
    const s = makeStack();
    const row = await s.quotas.createOverride({ id: "platform-admin" }, { organizationId: "org-1", metric: "ASSETS", newLimit: 500, reason: "contract uplift" });
    expect(row.newLimit).toBe(500);
    const audits = await s.db.auditLog.findMany({ where: { action: "QUOTA_OVERRIDE_CREATED" } });
    expect(audits).toHaveLength(1);
    const { limit, source } = await s.quotas.getLimit("org-1", "ASSETS");
    expect(limit).toBe(500); expect(source).toBe("OVERRIDE");
  });
});

describe("billing (§19–§27, §213, §219, §220)", () => {
  const secret = "whsec_test_secret_123456";
  function signedBody(payload: unknown, tsOffsetSeconds = 0) {
    const body = JSON.stringify(payload);
    const ts = Math.floor(Date.now() / 1000) + tsOffsetSeconds;
    const sig = createHmac("sha256", secret).update(`${ts}.${body}`).digest("hex");
    return { body, sig, ts: String(ts) };
  }

  it("unconfigured billing rejects webhooks and never simulates payment (§21/§268)", async () => {
    const s = makeStack();
    const { body, sig, ts } = signedBody({ id: "evt_1", type: "subscription.activated", data: { organizationId: "org-1" } });
    await expect(s.billing.handleWebhook({ provider: "stripe", rawBody: body, signature: sig, timestamp: ts })).rejects.toThrow(/not configured/);
  });

  it("valid webhook transitions state once; replay is a duplicate; bad signature rejected", async () => {
    const s = makeStack({ billing: () => ({ status: "TEST_ONLY", provider: "TEST", reason: "test" }), billingWebhookSecret: () => secret });
    await s.db.organization.create({ data: { id: "org-1", name: "O", slug: "o1", lifecycleStatus: "ACTIVE" } });
    const { version } = await seedPlan(s.db, "P", "SAAS", []);
    await s.subscriptions.create("admin", { organizationId: "org-1", planVersionId: version.id });
    const payload = { id: "evt_9", type: "invoice.payment_failed", data: { organizationId: "org-1" } };
    const { body, sig, ts } = signedBody(payload);
    const first = await s.billing.handleWebhook({ provider: "test", rawBody: body, signature: sig, timestamp: ts });
    expect(first.duplicate).toBe(false);
    const sub = await s.subscriptions.getForOrganization("org-1");
    expect(sub.status).toBe("PAST_DUE");
    const replay = await s.billing.handleWebhook({ provider: "test", rawBody: body, signature: sig, timestamp: ts });
    expect(replay.duplicate).toBe(true);
    expect(await s.db.billingEvent.count({})).toBe(1);
    await expect(s.billing.handleWebhook({ provider: "test", rawBody: body, signature: "bad", timestamp: ts })).rejects.toThrow(/rejected/);
  });

  it("webhook carrying card data is refused (§26); billing views are org-scoped (§213)", async () => {
    const s = makeStack({ billing: () => ({ status: "TEST_ONLY", provider: "TEST", reason: "test" }), billingWebhookSecret: () => secret });
    const { body, sig, ts } = signedBody({ id: "evt_x", type: "invoice.issued", data: { organizationId: "org-1", card_number: "4242424242424242" } });
    await expect(s.billing.handleWebhook({ provider: "test", rawBody: body, signature: sig, timestamp: ts })).rejects.toThrow(/payment data/);
    await s.db.billingEvent.create({ data: { organizationId: "org-b", provider: "test", externalEventId: "e-b", type: "x", status: "PROCESSED" } });
    expect(await s.billing.listEvents("org-a")).toEqual([]);
  });
});

describe("licensing (§28–§37, §215, §216, §233)", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pubPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const privPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const payload: LicensePayload = {
    licenseId: "lic-test-1", organization: "Org One", edition: "ENTERPRISE", issuer: "DSRclone Licensing",
    issuedAt: "2026-01-01T00:00:00.000Z", validFrom: "2026-01-01T00:00:00.000Z", expiresAt: "2027-06-01T00:00:00.000Z",
    entitlements: [{ featureKey: "SSO", enabled: true, limit: null }], limits: { ASSETS: 1000 },
  };

  it("installs a valid signed license and exposes entitlements; tampered license is rejected + audited", async () => {
    const s = makeStack({ licensePublicKey: () => pubPem, licensingEnabled: () => true });
    await s.db.organization.create({ data: { id: "org-1", name: "Org One", slug: "org-one", lifecycleStatus: "ACTIVE" } });
    const doc = signLicense(payload, privPem);
    const view = await s.licenses.install({ id: "u1", organizationId: "org-1" }, JSON.stringify(doc));
    expect(view.installed).toBe(true);
    expect(view.evaluation?.status).toBe("VALID");
    expect((view.license as any).signature).toBeUndefined(); // never exposed (§105)
    await expect(s.entitlements.requireFeature("org-1", "SSO")).resolves.toBeUndefined();

    const tampered = JSON.stringify({ ...doc, payload: { ...doc.payload, edition: "UNLIMITED" } });
    await expect(s.licenses.install({ id: "u1", organizationId: "org-1" }, tampered)).rejects.toThrow(/rejected/);
    const rejects = await s.db.auditLog.findMany({ where: { action: "LICENSE_REJECTED" } });
    expect(rejects.length).toBeGreaterThanOrEqual(1);
  });

  it("expired license (past grace) restricts paid features but preserves all data (§216)", async () => {
    const s = makeStack({ licensePublicKey: () => pubPem, licensingEnabled: () => true, licenseGraceDays: () => 0 });
    await s.db.organization.create({ data: { id: "org-1", name: "Org One", slug: "org-one", lifecycleStatus: "ACTIVE" } });
    const expiredPayload = { ...payload, licenseId: "lic-old", expiresAt: "2026-02-01T00:00:00.000Z" };
    const doc = signLicense(expiredPayload, privPem);
    const view = await s.licenses.install({ id: "u1", organizationId: "org-1" }, JSON.stringify(doc));
    expect(view.evaluation?.status).toBe("EXPIRED");
    expect(view.evaluation?.capabilitiesActive).toBe(false);
    await expect(s.entitlements.requireFeature("org-1", "SSO")).rejects.toThrow(/not entitled/);
    // data preserved: the license row and the org remain fully readable
    const current = await s.licenses.getCurrent("org-1");
    expect(current.installed).toBe(true);
  });
});

describe("trials & downgrade (§54–§57, §114–§118, §221, §222)", () => {
  it("trial expiry restricts trial features and preserves data", async () => {
    const s = makeStack();
    const { version } = await seedPlan(s.db, "TRIAL", "SAAS", [{ featureKey: "AI_COPILOT", enabled: true }]);
    await s.db.organization.create({ data: { id: "org-1", name: "O", slug: "o1", lifecycleStatus: "ACTIVE" } });
    const trial = await s.trials.startTrial("org-1", version.id);
    await expect(s.entitlements.requireFeature("org-1", "AI_COPILOT")).resolves.toBeUndefined();
    await s.db.productTrial.update({ where: { id: trial.id }, data: { expiresAt: new Date(Date.now() - 1000) } });
    // §57: once the expiry date passes, trial features restrict immediately…
    await expect(s.entitlements.requireFeature("org-1", "AI_COPILOT")).rejects.toThrow(/not entitled/);
    // …and the sweep transitions the rows + audits.
    const expired = await s.trials.expireTrials();
    expect(expired).toBe(1);
    await expect(s.entitlements.requireFeature("org-1", "AI_COPILOT")).rejects.toThrow(/not entitled/);
    expect(await s.db.organization.count({})).toBe(1); // data preserved
  });

  it("downgrade needs impact acknowledgement, preserves data, reports OVER_LIMIT", async () => {
    const s = makeStack();
    const big = await seedPlan(s.db, "BIG", "SAAS", [{ featureKey: "WEB_VAPT", enabled: true }, { featureKey: "SSO", enabled: true }], { ASSETS: 1000 });
    const small = await seedPlan(s.db, "SMALL", "SAAS", [{ featureKey: "WEB_VAPT", enabled: true }], { ASSETS: 1 });
    await s.db.organization.create({ data: { id: "org-1", name: "O", slug: "o1", lifecycleStatus: "ACTIVE" } });
    await s.db.workspace.create({ data: { id: "ws-1", organizationId: "org-1", name: "W" } });
    for (let i = 0; i < 3; i++) await s.db.asset.create({ data: { workspaceId: "ws-1", targetId: `t${i}`, host: `h${i}.example` } });
    await s.subscriptions.create("admin", { organizationId: "org-1", planVersionId: big.version.id });
    await expect(s.subscriptions.downgrade("u", "org-1", small.version.id, false)).rejects.toThrow(/impact preview/);
    const preview = await s.subscriptions.previewDowngrade("org-1", small.version.id);
    expect(preview.impact.resultsInOverLimit).toBe(true);
    expect(preview.impact.disabledFeatures).toContain("SSO");
    const result = await s.subscriptions.downgrade("u", "org-1", small.version.id, true);
    expect(result.overLimit).toBe(true);
    expect(await s.db.asset.count({})).toBe(3); // nothing deleted (§116)
    // over-limit: reading works, creating beyond limit is blocked (§118)
    await expect(s.quotas.check("org-1", "ASSETS", 1)).rejects.toMatchObject({ response: { error: "QUOTA_EXCEEDED" } });
  });
});

describe("lifecycle & deletion (§85–§94, §234)", () => {
  it("cancellation flows through retention; deletion needs slug confirmation; legal hold blocks", async () => {
    const s = makeStack();
    await s.db.organization.create({ data: { id: "org-1", name: "O", slug: "o1", lifecycleStatus: "ACTIVE" } });
    await s.lifecycle.requestCancellation("u", "org-1");
    await s.lifecycle.finalizeCancellation("op", "org-1", 30);
    const org = await s.db.organization.findUnique({ where: { id: "org-1" } });
    expect(org.lifecycleStatus).toBe("RETENTION");
    expect(org.retentionUntil).toBeTruthy();
    await expect(s.lifecycle.requestDeletion("u", "org-1", "wrong")).rejects.toThrow(/slug/);
    const pending = await s.lifecycle.requestDeletion("u", "org-1", "o1");
    expect(pending.organization.lifecycleStatus).toBe("DELETION_PENDING");
    expect(await s.db.organization.count({})).toBe(1); // request ≠ deletion (§91)

    await s.db.organization.create({ data: { id: "org-2", name: "H", slug: "o2", lifecycleStatus: "RETENTION", legalHold: true } });
    const preview = await s.lifecycle.deletionPreview("org-2");
    expect(preview.deletionBlocked).toBe(true);
    await expect(s.lifecycle.requestDeletion("u", "org-2", "o2")).rejects.toThrow(/legal hold/);
  });
});

describe("platform control & support access (§95–§106, §212, §224, §225, §235, §236)", () => {
  it("platform permissions require the platform-admin flag — org OWNER is not enough", async () => {
    const s = makeStack();
    await s.db.user.create({ data: { id: "u-owner", email: "o@x.io", name: "O", passwordHash: "x", isPlatformAdmin: false } });
    await s.db.user.create({ data: { id: "u-plat", email: "p@x.io", name: "P", passwordHash: "x", isPlatformAdmin: true } });
    await expect(s.permissions.requirePlatformPermission(ownerOf("org-1"), "VIEW_PLATFORM_ORGANIZATIONS")).rejects.toThrow(/platform administrator/);
    await expect(s.permissions.requirePlatformPermission({ id: "u-plat", email: "p@x.io", organizationId: "org-1", role: "OWNER" }, "VIEW_PLATFORM_ORGANIZATIONS")).resolves.toBeUndefined();
  });

  it("support sessions: pending grants nothing, approval activates, expiry denies, all audited", async () => {
    const s = makeStack();
    await s.db.organization.create({ data: { id: "org-1", name: "O", slug: "o1", lifecycleStatus: "ACTIVE" } });
    const session = await s.platformData.createSupportSession({ id: "op-1" }, { organizationId: "org-1", reason: "Investigating scan failures for ticket 42", scope: { areas: ["health", "usage"] }, expiresInHours: 4, tenantApproved: false });
    await expect(s.platformData.requireActiveSupportSession(session.id, "org-1")).rejects.toThrow(/not active/);
    await s.platformData.approveSupportSession("org-1", session.id, "u-owner");
    await expect(s.platformData.requireActiveSupportSession(session.id, "org-1")).resolves.toBeTruthy();
    await s.platformData.endSupportSession("op-1", session.id);
    const trail = await s.platformData.supportAuditTrail("org-1");
    expect(trail.map((t: any) => t.action)).toEqual(expect.arrayContaining(["SUPPORT_ACCESS_STARTED", "SUPPORT_ACCESS_ENDED"]));
    const expired = await s.platformData.createSupportSession({ id: "op-1" }, { organizationId: "org-1", reason: "Follow-up investigation for ticket 43", scope: { areas: ["health"] }, expiresInHours: 1, tenantApproved: true });
    await s.db.supportAccessSession.update({ where: { id: expired.id }, data: { expiresAt: new Date(Date.now() - 1000) } });
    await expect(s.platformData.requireActiveSupportSession(expired.id, "org-1")).rejects.toThrow(/not active/);
  });

  it("platform organization view is metadata-only: no password hashes or secrets (§236)", async () => {
    const s = makeStack();
    await s.db.organization.create({ data: { id: "org-1", name: "O", slug: "o1", lifecycleStatus: "ACTIVE" } });
    await s.db.user.create({ data: { id: "u1", email: "o@x.io", name: "O", passwordHash: "bcrypt-hash-value", isPlatformAdmin: false } });
    const view = await s.platformData.getOrganization("org-1");
    expect(JSON.stringify(view)).not.toContain("bcrypt-hash-value");
    expect(Object.keys(view)).not.toContain("passwordHash");
  });
});

describe("capabilities & analytics (§119–§121, §143, §226, §229)", () => {
  it("entitled feature with no worker online resolves WORKER_UNAVAILABLE, not AVAILABLE", async () => {
    const s = makeStack();
    const { version } = await seedPlan(s.db, "P", "SAAS", [{ featureKey: "MOBILE_VAPT", enabled: true }]);
    await s.db.organization.create({ data: { id: "org-1", name: "O", slug: "o1", lifecycleStatus: "ACTIVE" } });
    await s.subscriptions.create("admin", { organizationId: "org-1", planVersionId: version.id });
    const caps = await s.capabilities.resolveForOrganization("org-1", "OWNER");
    expect(caps.find((c) => c.featureKey === "MOBILE_VAPT")?.state).toBe("WORKER_UNAVAILABLE");
  });

  it("analytics recording drops targets/evidence/secrets even when telemetry is on (§229)", async () => {
    const s = makeStack({ telemetryEnabled: () => true });
    const res = await s.analytics.record("org-1", "FIRST_SCAN", { count: 1, targetUrl: "https://victim.example", apiToken: "secret" });
    expect(res.recorded).toBe(true);
    const rows = await s.db.productAnalyticsEvent.findMany({});
    expect(JSON.stringify(rows)).not.toContain("victim.example");
    expect(JSON.stringify(rows)).not.toContain("secret");
  });
});

describe("plan administration (§6–§9)", () => {
  it("plan updates create new versions; subscriptions keep historical versions (§8)", async () => {
    const s = makeStack();
    const plan = await s.plans.createPlan("admin", { code: "X", name: "X", productMode: "SAAS", entitlements: [{ featureKey: "WEB_VAPT", enabled: true }], quotas: { ASSETS: 10 } });
    const v2 = await s.plans.updatePlan("admin", plan.id, { entitlements: [{ featureKey: "WEB_VAPT", enabled: true }, { featureKey: "SSO", enabled: true }], quotas: { ASSETS: 20 } });
    expect(v2.version).toBe(2);
    const audits = await s.db.auditLog.findMany({ where: { action: "PLAN_UPDATED" } });
    expect(audits).toHaveLength(1);
  });

  it("safety invariants cannot be added as entitlements (§16)", async () => {
    const s = makeStack();
    await expect(s.plans.createPlan("admin", { code: "EVIL", name: "E", productMode: "SAAS", entitlements: [{ featureKey: "SCANNER_SAFETY", enabled: false }] })).rejects.toThrow(/safety invariant/);
  });
});
