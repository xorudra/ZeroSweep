import { describe, expect, it } from "vitest";
import {
  DEFAULT_RETRY_POLICY, DEFAULT_RETENTION, DEFAULT_SLOS, PLATFORM_PERMISSIONS,
  PLATFORM_AUDIT_ACTIONS, RESTORE_CONFIRMATION,
  connectionBudget, drAchievement, effectivePriority, evaluateProductionConfig,
  evaluateRestoreTarget, evaluateSli, evaluateWork, featureFlagEnabled,
  formatTraceparent, isSecretReference, isRetentionExpired, leaseState,
  metricLabelViolations, metricNameValid, operatorRetryAllowed, parseTraceparent,
  restoreValidationPassed, retentionExpiry, retryDecision, retryDelayMs,
  screenSpanAttributes, sha256Hex, validateReleaseMetadata, verifyBackupIntegrity,
  backupTransitionAllowed, restoreTransitionAllowed,
} from "./index";

describe("Prompt 38 platform vocabulary (§203/§204)", () => {
  it("carries exactly the spec permission set", () => {
    expect(PLATFORM_PERMISSIONS).toContain("RUN_RESTORE");
    expect(PLATFORM_PERMISSIONS).toHaveLength(9);
    expect(PLATFORM_AUDIT_ACTIONS).toHaveLength(15);
    expect(PLATFORM_AUDIT_ACTIONS).toContain("PRODUCTION_ROLLBACK_STARTED");
  });
});

describe("secret references (§21–§24)", () => {
  it("accepts reference forms and refuses plaintext", () => {
    expect(isSecretReference("env:PROD_DB_PASSWORD")).toBe(true);
    expect(isSecretReference("file:/run/secrets/db_password")).toBe(true);
    expect(isSecretReference("docker-secret:db_password")).toBe(true);
    expect(isSecretReference("k8s-secret:dsrclone/db/ password".replace(" ", ""))).toBe(true);
    expect(isSecretReference("vault:secret/data/db#password")).toBe(true);
    expect(isSecretReference("aws-sm:prod/dsrclone/db")).toBe(true);
    expect(isSecretReference("hunter2")).toBe(false);
    expect(isSecretReference("postgresql://u:p@host/db")).toBe(false);
  });
});

describe("production configuration (§16–§28)", () => {
  const good = {
    nodeEnv: "production",
    databaseUrl: "postgresql://u:p@db:5432/dsrclone?sslmode=require",
    databaseRequireTls: true, databaseConnectionLimit: 10,
    redisUrl: "rediss://redis:6379", redisRequireTls: true,
    jwtSecret: "x".repeat(40), corsOrigin: "https://app.example.org",
    secretRefs: { DB_SECRET_REF: "env:PROD_DB_PASSWORD" },
    dbConnectionBudget: 100, plannedReplicas: 3,
  };
  it("passes a well-formed production config", () => {
    expect(evaluateProductionConfig(good)).toEqual([]);
  });
  it("flags placeholders, wildcard CORS, bad refs and budget overruns by group", () => {
    const bad = evaluateProductionConfig({
      ...good,
      jwtSecret: "change-me-now",
      corsOrigin: "*",
      secretRefs: { DB_SECRET_REF: "hunter2" },
      plannedReplicas: 40,
    });
    const rules = bad.map((v) => v.rule);
    expect(rules).toContain("JWT_PLACEHOLDER");
    expect(rules).toContain("CORS_WILDCARD");
    expect(rules).toContain("SECRET_REF_FORM");
    expect(rules).toContain("DB_CONNECTION_BUDGET");
    expect(bad.every((v) => !v.message.includes("hunter2"))).toBe(true); // values never echoed
  });
  it("development imposes nothing", () => {
    expect(evaluateProductionConfig({ nodeEnv: "development" })).toEqual([]);
  });
  it("connection budget multiplies per-replica pools plus headroom (§27)", () => {
    expect(connectionBudget({ connectionLimitPerReplica: 10, replicas: 3, budget: 100 }))
      .toEqual({ planned: 40, budget: 100, withinBudget: true });
    expect(connectionBudget({ connectionLimitPerReplica: 10, replicas: 10, budget: 100 }).withinBudget).toBe(false);
  });
});

describe("queue policy (§41–§46)", () => {
  it("retry delays grow, stay bounded, and dead-letter at the cap", () => {
    const d1 = retryDelayMs(DEFAULT_RETRY_POLICY, 1, 0.5);
    const d3 = retryDelayMs(DEFAULT_RETRY_POLICY, 3, 0.5);
    expect(d3).toBeGreaterThan(d1);
    expect(retryDelayMs(DEFAULT_RETRY_POLICY, 99, 0.5)).toBeLessThanOrEqual(DEFAULT_RETRY_POLICY.maxDelayMs);
    expect(retryDecision(DEFAULT_RETRY_POLICY, 4).action).toBe("RETRY");
    expect(retryDecision(DEFAULT_RETRY_POLICY, 5)).toMatchObject({ action: "DEAD_LETTER" });
  });
  it("priority aging surfaces old low-priority jobs but caps below top priority", () => {
    expect(effectivePriority(10, 30 * 60_000)).toBe(40);
    expect(effectivePriority(95, 10_000 * 60_000)).toBe(99);
  });
  it("lease staleness is derived from heartbeat age", () => {
    const lease = { workerId: "w1", leasedAt: 0, heartbeatAt: 1_000, leaseMs: 10_000 };
    expect(leaseState(lease, 5_000)).toBe("ACTIVE");
    expect(leaseState(lease, 9_000)).toBe("STALE");
    expect(leaseState(lease, 12_000)).toBe("EXPIRED");
  });
  it("operator retry is limited to IDs-only governed job kinds", () => {
    expect(operatorRetryAllowed("SCAN_ORCHESTATION")).toBe(true);
    expect(operatorRetryAllowed("ARBITRARY_SHELL")).toBe(false);
    expect(operatorRetryAllowed(undefined)).toBe(false);
  });
});

describe("backup & restore (§160–§180, §232–§234)", () => {
  it("retention keeps the newest minimum regardless of age", () => {
    const old = new Date(Date.now() - 90 * 86_400_000);
    expect(isRetentionExpired({ createdAt: old, rank: 0 }, new Date())).toBe(false);
    expect(isRetentionExpired({ createdAt: old, rank: 9 }, new Date())).toBe(true);
    expect(retentionExpiry(old, DEFAULT_RETENTION).getTime()).toBe(old.getTime() + 30 * 86_400_000);
  });
  it("state machines never resurrect finished records", () => {
    expect(backupTransitionAllowed("STARTED", "COMPLETED")).toBe(true);
    expect(backupTransitionAllowed("COMPLETED", "STARTED")).toBe(false);
    expect(restoreTransitionAllowed("FAILED", "COMPLETED")).toBe(false);
  });
  it("integrity: checksum mismatch or missing checksum refuses (§234)", () => {
    const sum = sha256Hex("artifact");
    expect(verifyBackupIntegrity(sum, sum)).toEqual({ ok: true });
    expect(verifyBackupIntegrity(sum, sha256Hex("tampered")).ok).toBe(false);
    expect(verifyBackupIntegrity(null, sum).ok).toBe(false);
  });
  it("restore targets must be isolated recovery databases (§173)", () => {
    expect(RESTORE_CONFIRMATION).toBe("RESTORE_INTO_ISOLATED_ENVIRONMENT");
    expect(evaluateRestoreTarget({ targetDatabase: "dsrclone", productionDatabase: "dsrclone" }).ok).toBe(false);
    expect(evaluateRestoreTarget({ targetDatabase: "postgres", productionDatabase: "dsrclone" }).ok).toBe(false);
    expect(evaluateRestoreTarget({ targetDatabase: "dsrclone_copy", productionDatabase: "dsrclone" }).ok).toBe(false);
    expect(evaluateRestoreTarget({ targetDatabase: "dsrclone_restore", productionDatabase: "dsrclone" })).toEqual({ ok: true });
  });
  it("restore validation requires every check (§174)", () => {
    const all = { databaseConsistent: true, objectReferencesValid: true, reportAccessValid: true, findingHistoryPresent: true, tenantIsolationIntact: true };
    expect(restoreValidationPassed(all)).toBe(true);
    expect(restoreValidationPassed({ ...all, tenantIsolationIntact: false })).toBe(false);
  });
  it("RPO/RTO are NOT_MEASURED until an exercise measures them (§180)", () => {
    expect(drAchievement({ targetRpoSeconds: 3600 })).toEqual({ rpo: "NOT_MEASURED", rto: "NOT_MEASURED" });
    expect(drAchievement({ measuredRpoSeconds: 600, targetRpoSeconds: 3600 }).rpo).toBe("MEASURED");
    expect(drAchievement({ measuredRpoSeconds: 7200, targetRpoSeconds: 3600 }).rpo).toBe("MEASURED_ABOVE_TARGET");
  });
});

describe("SLO (§124–§127)", () => {
  it("computes ratio and error budget from real samples", () => {
    const r = evaluateSli(DEFAULT_SLOS[0]!, { successes: 99, total: 100 });
    expect(r.status).toBe("OK");
    expect(r.ratio).toBeCloseTo(0.99);
    const b = evaluateSli(DEFAULT_SLOS[0]!, { successes: 90, total: 100 });
    expect(b.status).toBe("BREACHED");
    expect(b.errorBudgetRemaining).toBeLessThan(0);
  });
  it("no samples means INSUFFICIENT_DATA, never a fabricated figure", () => {
    const r = evaluateSli(DEFAULT_SLOS[0]!, { successes: 0, total: 0 });
    expect(r.status).toBe("INSUFFICIENT_DATA");
    expect(r.ratio).toBeNull();
  });
});

describe("observability safety (§98/§107/§116)", () => {
  it("flags high-cardinality / identifying metric labels", () => {
    expect(metricLabelViolations({ route: "/x", user_id: "u1", finding_id: "f" })).toEqual(["user_id", "finding_id"]);
    expect(metricNameValid("dsrclone_http_requests_total")).toBe(true);
    expect(metricNameValid("http_requests")).toBe(false);
  });
  it("span screening removes secrets outright and drops payloads", () => {
    const out = screenSpanAttributes({ authorization: "Bearer x", route: "/a", payload: { a: 1 }, count: 3 });
    expect(out).toEqual({ route: "/a", count: 3 });
  });
  it("traceparent round-trips and rejects zero ids", () => {
    const ctx = { traceId: "a".repeat(32), parentSpanId: "b".repeat(16), sampled: true };
    expect(parseTraceparent(formatTraceparent(ctx))).toEqual(ctx);
    expect(parseTraceparent(`00-${"0".repeat(32)}-${"b".repeat(16)}-01`)).toBeNull();
    expect(parseTraceparent("garbage")).toBeNull();
  });
});

describe("release & operator controls (§147–§159)", () => {
  it("unknown feature flags are OFF", () => {
    expect(featureFlagEnabled("AI_V2_WORKFLOWS", { AI_V2_WORKFLOWS: true })).toBe(true);
    expect(featureFlagEnabled("AI_V2_WORKFLOWS", {})).toBe(false);
    expect(featureFlagEnabled("NOT_A_FLAG", { NOT_A_FLAG: true })).toBe(false);
  });
  it("release metadata requires version + SHA commit (§156)", () => {
    expect(validateReleaseMetadata({ version: "1.0.0", commit: "1eb3310", environment: "production" })).toEqual([]);
    expect(validateReleaseMetadata({ version: "1.0.0", commit: "not-a-sha", environment: "production" })).toHaveLength(1);
  });
  it("kill switches block only their work class; maintenance blocks all work classes; reads never block", () => {
    const control = {
      maintenanceMode: false,
      killSwitches: { SCAN_STARTS: { enabled: true, reason: "incident" } },
    };
    expect(evaluateWork(control, "SCAN_START").allowed).toBe(false);
    expect(evaluateWork(control, "REPORT_JOB").allowed).toBe(true);
    expect(evaluateWork(control, "READ").allowed).toBe(true);
    expect(evaluateWork({ maintenanceMode: true, killSwitches: {} }, "AI_REQUEST").allowed).toBe(false);
    expect(evaluateWork({ maintenanceMode: true, killSwitches: {} }, "ADMIN").allowed).toBe(true);
    expect(evaluateWork(null, "SCAN_START").allowed).toBe(true);
  });
});
