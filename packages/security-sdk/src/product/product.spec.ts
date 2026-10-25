import { describe, expect, it } from "vitest";
import { generateKeyPairSync } from "node:crypto";
import {
  PRODUCT_FEATURE_REGISTRY, FEATURE_KEYS, resolveCommercialToolStatus,
  EXAMPLE_PLANS, isReservedSlug, isValidSlug,
  computeEffectiveEntitlements, findEntitlement, resolveCapability, isSafetyInvariantKey, SAFETY_INVARIANTS,
  signLicense, evaluateLicense, parseLicenseDocument, type LicensePayload,
  billingConfigurationStatus, verifyBillingWebhookSignature, findPaymentDataViolations, looksLikeCardNumber,
  USAGE_METRIC_DEFINITIONS, USAGE_METRICS, evaluateQuota, quotaExceededBody, aggregateUsage, FAIR_USE_CEILINGS,
  canTransitionLifecycle, lifecycleAllowsNewWork, computeDowngradeImpact, computeDeletionImpact,
  ONBOARDING_STEPS, onboardingProgress, canCompleteStep, ONBOARDING_DEFAULT_ASSESSMENT_PROFILE,
  evaluateAbuseResponse, isProtectedTarget, sanitizeAnalyticsProperties,
  redactConfigForDiagnostics, sanitizeDiagnosticText, buildDiagnosticBundle,
  evaluateUpgradePreflight, isWorkerVersionCompatible,
  evaluateLaunchGates, buildDemoDataset, demoModeAllows, DEMO_DATA_LABEL,
  hasBillingPermission, PRODUCT_AUDIT_ACTIONS,
} from "./index";
import { createHmac } from "node:crypto";

describe("feature registry (§10/§11)", () => {
  it("registers every stable feature key with metering + enforcement strategies", () => {
    expect(PRODUCT_FEATURE_REGISTRY).toHaveLength(FEATURE_KEYS.length);
    for (const f of PRODUCT_FEATURE_REGISTRY) {
      expect(f.displayName.length).toBeGreaterThan(0);
      expect(f.technicalDependency.length).toBeGreaterThan(0);
      expect(f.meteringStrategy).toBeDefined();
      expect(f.enforcementStrategy).toBeDefined();
    }
  });
  it("commercial tools are never bundled: unconfigured => LICENSE_REQUIRED (§123/§227)", () => {
    expect(resolveCommercialToolStatus({ customerConfigured: false, connectorReachable: null })).toBe("LICENSE_REQUIRED");
    expect(resolveCommercialToolStatus({ customerConfigured: true, connectorReachable: true })).toBe("CONFIGURED");
    expect(resolveCommercialToolStatus({ customerConfigured: true, connectorReachable: false })).toBe("UNAVAILABLE");
  });
});

describe("example plans (§256–§259)", () => {
  it("seed plans carry no pricing (pricing is separate configuration, §257)", () => {
    for (const p of EXAMPLE_PLANS) expect(p.price).toBeNull();
  });
  it("reserved slugs are blocked (§64)", () => {
    expect(isReservedSlug("admin")).toBe(true);
    expect(isValidSlug("admin")).toBe(false);
    expect(isValidSlug("acme-security")).toBe(true);
    expect(isValidSlug("Bad Slug")).toBe(false);
  });
});

describe("effective entitlements (§13–§16)", () => {
  const plan = [{ featureKey: "WEB_VAPT" as const, enabled: true, limit: 10 }, { featureKey: "SSO" as const, enabled: false, limit: null }];
  it("license wins over plan; plan disable cannot be re-enabled by trial", () => {
    const eff = computeEffectiveEntitlements({
      license: [{ featureKey: "WEB_VAPT", enabled: true, limit: 99 }],
      plan,
      trial: [{ featureKey: "SSO", enabled: true, limit: null }],
      limitOverrides: [],
    });
    expect(findEntitlement(eff, "WEB_VAPT")).toMatchObject({ enabled: true, limit: 99, source: "LICENSE" });
    expect(findEntitlement(eff, "SSO").enabled).toBe(false);
  });
  it("approved overrides only raise limits of enabled features (§138)", () => {
    const eff = computeEffectiveEntitlements({ license: null, plan, trial: null, limitOverrides: [{ featureKey: "WEB_VAPT", limit: 50 }] });
    expect(findEntitlement(eff, "WEB_VAPT").limit).toBe(50);
  });
  it("unentitled features resolve disabled (fail closed)", () => {
    const eff = computeEffectiveEntitlements({ license: null, plan: [], trial: null, limitOverrides: [] });
    expect(findEntitlement(eff, "AI_COPILOT")).toMatchObject({ enabled: false, source: "NONE" });
  });
  it("safety invariants are not features and can never be entitled (§16)", () => {
    for (const inv of SAFETY_INVARIANTS) expect(isSafetyInvariantKey(inv)).toBe(true);
    expect(isSafetyInvariantKey("WEB_VAPT")).toBe(false);
  });
});

describe("capability resolution (§119–§121, §226)", () => {
  const base = { entitled: true, deployed: true, toolAvailable: true, workerAvailable: true, authorized: true, quotaAvailable: true, temporarilyDisabled: false };
  it("entitled but worker missing => WORKER_UNAVAILABLE (entitled-but-unavailable)", () => {
    expect(resolveCapability("MOBILE_VAPT", { ...base, workerAvailable: false }).state).toBe("WORKER_UNAVAILABLE");
  });
  it("not entitled => NOT_ENTITLED before any other state", () => {
    expect(resolveCapability("SSO", { ...base, entitled: false, authorized: false }).state).toBe("NOT_ENTITLED");
  });
  it("all facts good => AVAILABLE", () => {
    expect(resolveCapability("WEB_VAPT", base).state).toBe("AVAILABLE");
  });
});

describe("signed licensing (§28–§37, §215/§216)", () => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const pubPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const privPem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const payload: LicensePayload = {
    licenseId: "lic-1", organization: "org-1", edition: "ENTERPRISE", issuer: "ZeroSweep Licensing",
    issuedAt: "2026-01-01T00:00:00.000Z", validFrom: "2026-01-01T00:00:00.000Z", expiresAt: "2027-01-01T00:00:00.000Z",
    entitlements: [{ featureKey: "WEB_VAPT", enabled: true, limit: null }], limits: { ASSETS: 100 },
  };
  const now = new Date("2026-06-01T00:00:00.000Z");

  it("valid signed license verifies", () => {
    const lic = signLicense(payload, privPem);
    expect(evaluateLicense(lic, pubPem, { now, graceDays: 14 }).status).toBe("VALID");
  });
  it("tampered license fails validation (§215)", () => {
    const lic = signLicense(payload, privPem);
    const tampered = { ...lic, payload: { ...lic.payload, limits: { ASSETS: 100000 } } };
    expect(evaluateLicense(tampered, pubPem, { now, graceDays: 14 }).status).toBe("INVALID");
  });
  it("expired license restricts paid features but preserves data; grace keeps capabilities (§216)", () => {
    const lic = signLicense(payload, privPem);
    const after = new Date("2027-01-10T00:00:00.000Z");
    const ev = evaluateLicense(lic, pubPem, { now: after, graceDays: 14 });
    expect(ev.status).toBe("EXPIRED");
    expect(ev.inGracePeriod).toBe(true);
    expect(ev.capabilitiesActive).toBe(true);
    const afterGrace = evaluateLicense(lic, pubPem, { now: new Date("2027-03-01T00:00:00.000Z"), graceDays: 14 });
    expect(afterGrace.capabilitiesActive).toBe(false);
    expect(afterGrace.reason).toMatch(/data.*preserved/i);
  });
  it("revoked and wrong-organization licenses fail", () => {
    const lic = signLicense(payload, privPem);
    expect(evaluateLicense(lic, pubPem, { now, graceDays: 14, revokedLicenseIds: new Set(["lic-1"]) }).status).toBe("REVOKED");
    expect(evaluateLicense(lic, pubPem, { now, graceDays: 14, expectedOrganization: "org-2" }).status).toBe("INVALID");
  });
  it("parse rejects malformed documents", () => {
    expect(() => parseLicenseDocument("{}")).toThrow();
  });
});

describe("billing (§19–§27, §220)", () => {
  it("no provider configured => NOT_CONFIGURED, never simulated (§21/§268)", () => {
    expect(billingConfigurationStatus({ provider: null, nodeEnv: "production" }).status).toBe("NOT_CONFIGURED");
    expect(billingConfigurationStatus({ provider: "test", nodeEnv: "production" }).status).toBe("NOT_CONFIGURED");
    expect(billingConfigurationStatus({ provider: "test", nodeEnv: "development" }).status).toBe("TEST_ONLY");
    expect(billingConfigurationStatus({ provider: "manual", nodeEnv: "production" }).status).toBe("CONFIGURED");
  });
  it("webhook signature verification accepts valid and rejects invalid (§220)", () => {
    const secret = "whsec_test_value_123456";
    const body = JSON.stringify({ id: "evt_1", type: "subscription.updated" });
    const ts = Math.floor(Date.now() / 1000);
    const sig = createHmac("sha256", secret).update(`${ts}.${body}`).digest("hex");
    expect(verifyBillingWebhookSignature({ rawBody: body, signatureHeader: sig, timestampHeader: String(ts), secret, now: new Date() }).ok).toBe(true);
    expect(verifyBillingWebhookSignature({ rawBody: body, signatureHeader: "deadbeef", timestampHeader: String(ts), secret, now: new Date() }).ok).toBe(false);
    expect(verifyBillingWebhookSignature({ rawBody: body, signatureHeader: sig, timestampHeader: String(ts - 10_000), secret, now: new Date() }).ok).toBe(false);
  });
  it("raw card data is detected and refused (§26)", () => {
    expect(looksLikeCardNumber("4242 4242 4242 4242")).toBe(true);
    expect(findPaymentDataViolations({ card_number: "4242424242424242" }).length).toBeGreaterThan(0);
    expect(findPaymentDataViolations({ note: "4242424242424242" }).length).toBeGreaterThan(0);
    expect(findPaymentDataViolations({ amount: 100, currency: "USD" })).toEqual([]);
  });
});

describe("usage & quota (§38–§53)", () => {
  it("every metric has exactly one canonical definition (§41)", () => {
    for (const m of USAGE_METRICS) expect(USAGE_METRIC_DEFINITIONS[m].length).toBeGreaterThan(10);
  });
  it("quota evaluation + structured failure body (§48/§51)", () => {
    const ev = evaluateQuota({ dimension: "ASSETS", currentUsage: 25, requested: 1, limit: 25 });
    expect(ev.allowed).toBe(false);
    expect(quotaExceededBody(ev, "2026-10", true)).toMatchObject({ error: "QUOTA_EXCEEDED", quota: "ASSETS", limit: 25 });
    expect(evaluateQuota({ dimension: "ASSETS", currentUsage: 25, requested: 1, limit: null }).allowed).toBe(true);
  });
  it("aggregation derives from raw events (§43/§44)", () => {
    const agg = aggregateUsage([
      { metric: "SCAN_JOBS", quantity: 1, occurredAt: new Date("2026-10-08T10:00:00Z") },
      { metric: "SCAN_JOBS", quantity: 2, occurredAt: new Date("2026-10-08T22:00:00Z") },
      { metric: "SCAN_JOBS", quantity: 1, occurredAt: new Date("2026-10-09T01:00:00Z") },
    ], "DAILY");
    expect(agg).toHaveLength(2);
    expect(agg[0].quantity).toBe(3);
  });
  it("fair-use ceilings exist independent of plan (§53)", () => {
    expect(FAIR_USE_CEILINGS.MAX_UPLOAD_BYTES).toBeGreaterThan(0);
  });
});

describe("lifecycle & downgrade (§85–§118, §221)", () => {
  it("transitions are controlled; DELETED is never direct from ACTIVE", () => {
    expect(canTransitionLifecycle("ACTIVE", "CANCELLATION_PENDING")).toBe(true);
    expect(canTransitionLifecycle("ACTIVE", "DELETED")).toBe(false);
    expect(canTransitionLifecycle("RETENTION", "DELETION_PENDING")).toBe(true);
    expect(lifecycleAllowsNewWork("SUSPENDED")).toBe(false);
    expect(lifecycleAllowsNewWork("ACTIVE")).toBe(true);
  });
  it("downgrade preserves data and yields OVER_LIMIT facts (§221)", () => {
    const impact = computeDowngradeImpact({ usage: { ASSETS: 500, USERS: 3 }, newLimits: { ASSETS: 100, USERS: 10 }, disabledFeatures: ["SSO"], runningScheduledJobs: 2 });
    expect(impact.resultsInOverLimit).toBe(true);
    expect(impact.dataDeleted).toBe(false);
    expect(impact.overLimitDimensions).toEqual([{ dimension: "ASSETS", usage: 500, limit: 100 }]);
  });
  it("legal hold blocks deletion (§94)", () => {
    const impact = computeDeletionImpact({ workspaces: 1, assets: 2, findings: 3, reports: 1, evidenceItems: 0, integrations: 0, users: 1, usageEvents: 9 }, true);
    expect(impact.deletionBlocked).toBe(true);
  });
});

describe("onboarding (§65–§75)", () => {
  it("has the specified steps; safe default profile; ordered completion", () => {
    expect(ONBOARDING_STEPS.map((s) => s.key)).toContain("SECURITY_SCOPE");
    expect(ONBOARDING_DEFAULT_ASSESSMENT_PROFILE).toBe("SAFE_STANDARD");
    expect(canCompleteStep("FIRST_ASSESSMENT", []).ok).toBe(false);
    expect(onboardingProgress(["WELCOME"]).percent).toBe(10);
  });
});

describe("abuse prevention (§169–§175)", () => {
  it("protected-target attempts block scan creation; signals are not guilt", () => {
    expect(evaluateAbuseResponse({ PROTECTED_TARGET_ATTEMPT: 1 }).response).toBe("BLOCK_SCAN_CREATION");
    expect(evaluateAbuseResponse({ AUTHORIZATION_FAILURES: 1 }).response).toBe("WARN");
    expect(isProtectedTarget("169.254.169.254")).toBe(true);
    expect(isProtectedTarget("http://metadata.google.internal/latest")).toBe(true);
    expect(isProtectedTarget("example.com")).toBe(false);
  });
});

describe("analytics privacy (§143, §229)", () => {
  it("targets, evidence, secrets and domains never survive sanitization", () => {
    const { properties, droppedKeys } = sanitizeAnalyticsProperties({
      count: 3, planCode: "TRIAL", targetUrl: "https://victim.example", findingEvidence: "x", customerDomain: "acme.com", contactEmail: "a@b.co",
    });
    expect(properties).toEqual({ count: 3, planCode: "TRIAL" });
    expect(droppedKeys).toContain("targetUrl");
    expect(droppedKeys).toContain("findingEvidence");
  });
});

describe("diagnostics redaction (§208, §230)", () => {
  it("synthetic secrets never appear in the bundle", () => {
    const bundle = buildDiagnosticBundle({
      releaseVersion: "1.0.0", productMode: "SAAS", generatedAt: new Date(),
      serviceHealth: { api: "ok" }, workerHealth: [], queueStatus: [],
      configuration: { JWT_SECRET: "supersecretvalue", DATABASE_URL: "postgresql://u:p@h/db", PRODUCT_MODE: "SAAS" },
      recentErrors: ["failed with key AKIAIOSFODNN7EXAMPLE attached"],
    });
    const text = JSON.stringify(bundle);
    expect(text).not.toContain("supersecretvalue");
    expect(text).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(bundle.configuration.JWT_SECRET).toBe("[configured]");
    expect(redactConfigForDiagnostics({ A: "1" }).A).toBe("1");
    expect(sanitizeDiagnosticText("Bearer abcdefghijklmnopqrstuvwxyz")).toContain("[redacted]");
  });
});

describe("upgrade preflight (§190–§195)", () => {
  it("blocks upgrade without a successful backup or with incompatible workers", () => {
    const r = evaluateUpgradePreflight({
      currentVersion: "1.0.0", targetVersion: "1.1.0", pendingMigrations: 1,
      latestBackupStatus: "NONE", latestBackupAgeHours: null,
      freeDiskBytes: 10, requiredDiskBytes: 5, workerVersions: ["0.9"], compatibleWorkerVersions: ["1.0"],
      deprecatedSettingsPresent: [],
    });
    expect(r.canUpgrade).toBe(false);
    expect(r.blockers.length).toBeGreaterThanOrEqual(2);
    expect(isWorkerVersionCompatible("1.2")).toBe(true);
    expect(isWorkerVersionCompatible("0.9")).toBe(false);
  });
});

describe("launch gates (§267–§272)", () => {
  const passOutcomes = Object.fromEntries(
    ["RC_SECURITY", "TENANT_ISOLATION", "AUTHORIZATION", "PRODUCT_ENTITLEMENT", "QUOTA", "METERING", "LICENSE_SECURITY", "ONBOARDING", "BACKUP", "RESTORE", "PRODUCTION_DEPLOYMENT", "DOCUMENTATION", "NO_BLOCKER_DEFECTS"].map((g) => [g, { outcome: "PASS" as const, evidence: "recorded" }]),
  );
  it("billing gate is NOT_APPLICABLE (not fake PASS) when billing is unconfigured (§268)", () => {
    const ev = evaluateLaunchGates({ outcomes: passOutcomes, billingConfigured: false, selfHostedLicensingEnabled: true });
    expect(ev.gates.find((g) => g.gate === "BILLING_SECURITY")?.outcome).toBe("NOT_APPLICABLE");
    expect(ev.status).toBe("V1_READY");
  });
  it("any applicable failure => V1_BLOCKED with the exact failure (§272)", () => {
    const ev = evaluateLaunchGates({ outcomes: { ...passOutcomes, QUOTA: { outcome: "FAIL", evidence: "race test failed" } }, billingConfigured: false, selfHostedLicensingEnabled: false });
    expect(ev.status).toBe("V1_BLOCKED");
    expect(ev.blockers[0]).toContain("QUOTA");
  });
  it("a gate with no recorded evidence fails (§297)", () => {
    const ev = evaluateLaunchGates({ outcomes: {}, billingConfigured: true, selfHostedLicensingEnabled: true });
    expect(ev.status).toBe("V1_BLOCKED");
  });
});

describe("demo mode (§176–§180, §228)", () => {
  it("demo data is labelled synthetic; demo can view but never scan", () => {
    expect(buildDemoDataset().label).toBe(DEMO_DATA_LABEL);
    expect(demoModeAllows("VIEW")).toBe(true);
    expect(demoModeAllows("START_SCAN")).toBe(false);
  });
});

describe("product RBAC + audit vocabulary (§135–§137)", () => {
  it("billing permissions are role-scoped; audit actions cover §137", () => {
    expect(hasBillingPermission("OWNER", "MANAGE_BILLING")).toBe(true);
    expect(hasBillingPermission("VIEWER", "MANAGE_BILLING")).toBe(false);
    expect(hasBillingPermission("VIEWER", "VIEW_USAGE")).toBe(true);
    expect(PRODUCT_AUDIT_ACTIONS).toContain("LICENSE_INSTALLED");
    expect(PRODUCT_AUDIT_ACTIONS).toHaveLength(22);
  });
});
