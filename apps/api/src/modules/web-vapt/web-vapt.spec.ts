import { BadRequestException, ForbiddenException, NotFoundException } from "@nestjs/common";
import type { Role } from "@zerosweep/types";
import { WebVaptService } from "./web-vapt.service";
import { AuditService } from "../audit/audit.service";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Web/API VAPT V2 API tests (Prompt 32 §165–§168, §173–§180 service
 * posture, §192 cross-tenant, §196/§197 AI refusals) against an
 * in-memory Prisma fake. The governance chain is the subject:
 * VERIFIED target + APPROVED assessment before a target exists; the
 * §16 HIGH-module gate; budget clamping; honest NOT_CONFIGURED
 * preflight; spec host validation; matrix candidates; AI refusals.
 */

type Row = Record<string, any>;
let seq = 0;

function makeTable(rows: Row[] = []) {
  const matches = (row: Row, where: Row = {}) =>
    Object.entries(where).every(([k, v]) => {
      if (v === null || typeof v !== "object" || v instanceof Date) return row[k] === v || (v === null && (row[k] === null || row[k] === undefined));
      return true; // relation filters are out of scope for the fake
    });
  return {
    rows,
    async findFirst(args: { where?: Row } = {}) { return rows.find((r) => matches(r, args.where)) ?? null; },
    async findMany(args: { where?: Row; take?: number } = {}) {
      const found = rows.filter((r) => matches(r, args.where));
      return args.take ? found.slice(0, args.take) : found;
    },
    async count(args: { where?: Row } = {}) { return rows.filter((r) => matches(r, args.where)).length; },
    async create(args: { data: Row }) {
      const row = { id: `row-${++seq}`, createdAt: new Date(), updatedAt: new Date(), ...args.data };
      rows.push(row);
      return row;
    },
    async update(args: { where: Row; data: Row }) {
      const row = rows.find((r) => matches(r, args.where));
      if (!row) throw new Error("not found");
      Object.assign(row, args.data);
      return row;
    },
    async deleteMany(args: { where?: Row } = {}) {
      const before = rows.length;
      for (let i = rows.length - 1; i >= 0; i--) if (matches(rows[i]!, args.where)) rows.splice(i, 1);
      return { count: before - rows.length };
    },
  };
}

function makeService() {
  const db = {
    workspace: makeTable([{ id: "ws-1", organizationId: "org-1", deletedAt: null, createdAt: new Date() }]),
    asset: makeTable([{ id: "asset-1", workspaceId: "ws-1" }]),
    target: makeTable([
      { id: "target-1", workspaceId: "ws-1", verified: true },
      { id: "target-2", workspaceId: "ws-1", verified: false },
      { id: "target-3", workspaceId: "ws-1", verified: true },
    ]),
    targetVerification: makeTable([]),
    assessment: makeTable([{ id: "assess-1", workspaceId: "ws-1", targetId: "target-1", status: "APPROVED", createdBy: "u-creator", approvedBy: "u-approver" }]),
    authenticationProfile: makeTable([]),
    webVaptTarget: makeTable([
      { id: "wvt-other", workspaceId: "ws-other", assetId: "asset-1", targetId: "target-1", authorizationId: "assess-1", normalizedOrigin: "https://staging.example.com", environment: "STAGING", scanProfileKey: "WEB_SAFE" },
    ]),
    webVaptPreflightResult: makeTable([]),
    webVaptScanPlan: makeTable([]),
    scanScopeSnapshot: makeTable([]),
    scan: makeTable([]),
    endpoint: makeTable([]),
    webVaptEvidence: makeTable([]),
    webVaptCoverage: makeTable([]),
    apiService: makeTable([{ id: "svc-1", workspaceId: "ws-1", assetId: "asset-1", baseUrl: "https://staging.example.com", host: "staging.example.com", apiType: "REST", scopeStatus: "IN_SCOPE", source: "TEST" }]),
    apiSpecification: makeTable([]),
    apiSpecificationSnapshot: makeTable([]),
    authorizationTestCase: makeTable([{ id: "tc-1", workspaceId: "ws-1" }]),
    authorizationMatrixEntry: makeTable([]),
    businessLogicScenario: makeTable([]),
    webToolHealth: makeTable([]),
    auditLog: makeTable([]),
  };
  const service = new WebVaptService(db as never, new AuditService(db as never));
  return { service, db };
}

const user = (role: Role): RequestUser => ({ id: "user-1", email: "rudra@example.com", organizationId: "org-1", role });
const H: Record<string, string> = {};
const TARGET_BODY = { assetId: "asset-1", targetId: "target-1", baseUrl: "https://staging.example.com/app", environment: "STAGING" };

describe("targets (§4/§6)", () => {
  it("creates a target bound to the verified asset + APPROVED assessment, with audit", async () => {
    const { service, db } = makeService();
    const row = await service.createTarget(user("SECURITY_ENGINEER"), H, TARGET_BODY);
    expect(row.normalizedOrigin).toBe("https://staging.example.com");
    expect(row.authorizationId).toBe("assess-1");
    expect(db.auditLog.rows.some((r) => r.action === "WEB_VAPT_TARGET_CREATED")).toBe(true);
  });
  it("refuses an unverified parent target (§6)", async () => {
    const { service } = makeService();
    await expect(service.createTarget(user("ADMIN"), H, { ...TARGET_BODY, targetId: "target-2" })).rejects.toBeInstanceOf(BadRequestException);
  });
  it("refuses when no APPROVED assessment exists (§6/§173)", async () => {
    const { service } = makeService();
    await expect(service.createTarget(user("ADMIN"), H, { ...TARGET_BODY, targetId: "target-3" })).rejects.toBeInstanceOf(BadRequestException);
  });
  it("VIEWER cannot create targets (§166)", async () => {
    const { service } = makeService();
    await expect(service.createTarget(user("VIEWER"), H, TARGET_BODY)).rejects.toBeInstanceOf(ForbiddenException);
  });
  it("cross-tenant: another workspace's target is a 404 (§192)", async () => {
    const { service } = makeService();
    await expect(service.getTarget(user("ADMIN"), H, "wvt-other")).rejects.toBeInstanceOf(NotFoundException);
  });
});

describe("plans + the §16 HIGH gate (§10/§11/§127/§167)", () => {
  async function withTarget() {
    const ctx = makeService();
    const target = await ctx.service.createTarget(user("ADMIN"), H, TARGET_BODY);
    return { ...ctx, targetId: target.id as string };
  }
  it("plan freezes a hashed scope snapshot and clamps the budget to the ceiling", async () => {
    const { service, targetId } = await withTarget();
    const { plan, scopeSnapshot, budgetNotice } = await service.createPlan(user("ADMIN"), H, targetId, { profileKey: "WEB_SAFE", budget: { maxRequests: 100_000_000 } });
    expect(scopeSnapshot.hash).toMatch(/^[a-f0-9]{64}$/);
    expect((plan.budget as Row).maxRequests).toBe(100_000);
    expect(budgetNotice).toContain("clamped");
    expect(plan.allowedTools).toContain("nuclei");
    expect(plan.allowedTools).not.toContain("sqlmap");
  });
  it("HIGH module is blocked for an ANALYST (no RUN_HIGH_RISK_WEB_TESTS)", async () => {
    const { service, targetId } = await withTarget();
    const { plan, blockedModules } = await service.createPlan(user("ANALYST"), H, targetId, { profileKey: "WEB_STANDARD", highRiskModules: ["sqlmap"], approvalRef: "appr-1" });
    expect(plan.allowedTools).not.toContain("sqlmap");
    expect(blockedModules[0]?.slug).toBe("sqlmap");
  });
  it("HIGH module is blocked for an ADMIN without a recorded approval (§16)", async () => {
    const { service, targetId } = await withTarget();
    const { blockedModules } = await service.createPlan(user("ADMIN"), H, targetId, { profileKey: "WEB_STANDARD", highRiskModules: ["sqlmap"] });
    expect(blockedModules).toHaveLength(1);
  });
  it("HIGH module passes for an ADMIN with permission + approval, and the approval is audited", async () => {
    const { service, db, targetId } = await withTarget();
    const { plan } = await service.createPlan(user("ADMIN"), H, targetId, { profileKey: "WEB_STANDARD", highRiskModules: ["sqlmap"], approvalRef: "change-4711" });
    expect(plan.allowedTools).toContain("sqlmap");
    expect(db.auditLog.rows.some((r) => r.action === "HIGH_RISK_TEST_APPROVED")).toBe(true);
  });
});

describe("preflight + scan start (§7/§8)", () => {
  it("preflight is honestly BLOCKED with a NOT_CONFIGURED probe transport", async () => {
    const { service } = makeService();
    const target = await service.createTarget(user("ADMIN"), H, TARGET_BODY);
    const result = await service.runPreflight(user("ADMIN"), H, target.id as string);
    expect(result.status).toBe("BLOCKED");
    expect(result.probeTransport).toBe("NOT_CONFIGURED");
  });
  it("scan start is refused while preflight blocks — no canonical Scan is fabricated", async () => {
    const { service, db } = makeService();
    const target = await service.createTarget(user("ADMIN"), H, TARGET_BODY);
    const { plan } = await service.createPlan(user("ADMIN"), H, target.id as string, { profileKey: "WEB_SAFE" });
    await expect(service.startScan(user("ADMIN"), H, target.id as string, { planId: plan.id })).rejects.toBeInstanceOf(BadRequestException);
    expect(db.scan.rows).toHaveLength(0);
    expect(db.webVaptScanPlan.rows.find((r) => r.id === plan.id)?.status).toBe("BLOCKED");
  });
  it("cancel flips a started plan to CANCELLED with audit (§128/§168)", async () => {
    const { service, db } = makeService();
    db.webVaptScanPlan.rows.push({ id: "plan-x", workspaceId: "ws-1", webTargetId: "wvt-1", scanId: "scan-1", status: "STARTED" });
    const updated = await service.cancelScan(user("ANALYST"), H, "scan-1");
    expect(updated.status).toBe("CANCELLED");
    expect(db.auditLog.rows.some((r) => r.action === "WEB_VAPT_SCAN_CANCELLED")).toBe(true);
  });
});

describe("API specifications (§35–§40/§139–§141)", () => {
  const DOC = JSON.stringify({
    openapi: "3.0.0",
    info: { title: "Fixture API", version: "2.1.0" },
    servers: [{ url: "https://staging.example.com/v1" }, { url: "https://api.partner.example.net/v9" }],
    paths: { "/users": { get: {} }, "/orders": { get: {} } },
    components: { schemas: { User: { type: "object" } } },
  });
  it("imports through the governed posture: hosts validated, snapshot frozen, raw doc not stored", async () => {
    const { service, db } = makeService();
    const result = await service.importSpecification(user("SECURITY_ENGINEER"), H, { serviceId: "svc-1", format: "OPENAPI", document: DOC });
    expect(result.acceptedHosts).toEqual(["staging.example.com"]);
    expect(result.rejectedHosts).toEqual(["api.partner.example.net"]);
    expect(result.snapshot.endpointCount).toBe(2);
    expect(result.snapshot.hash).toMatch(/^[a-f0-9]{64}$/);
    const stored = db.apiSpecification.rows[0]!;
    expect(stored.document).toBeUndefined();
    expect(stored.checksum).toBe(result.snapshot.hash);
    expect(db.auditLog.rows.some((r) => r.action === "API_SPEC_IMPORTED")).toBe(true);
  });
  it("API scan planning uses API profiles only (§46/§122)", async () => {
    const { service } = makeService();
    await expect(service.startApiScan(user("ANALYST"), H, "svc-1", { profileKey: "WEB_STANDARD" })).rejects.toBeInstanceOf(BadRequestException);
    const ok = await service.startApiScan(user("ANALYST"), H, "svc-1", { profileKey: "API_SAFE" });
    expect(ok.status).toBe("PLANNED");
  });
});

describe("authorization matrix + scenarios (§97–§102)", () => {
  it("mismatch persists a candidate finding (CWE-862), never a bare Finding", async () => {
    const { service, db } = makeService();
    const result = await service.evaluateMatrix(user("ANALYST"), H, "tc-1", {
      rows: [
        { identityA: "fixture:user-a", identityB: "fixture:user-b", role: "USER", resource: "fixture:invoice/{id}", expectedAccess: "DENY", observedAccess: "ALLOW" },
        { identityA: "fixture:user-a", role: "USER", resource: "fixture:own-profile", expectedAccess: "ALLOW", observedAccess: "ALLOW" },
      ],
    });
    expect(result.summary).toEqual({ total: 2, matches: 1, mismatches: 1, untested: 0 });
    const entry = db.authorizationMatrixEntry.rows.find((r) => r.result === "MISMATCH");
    expect((entry?.candidateFinding as Row)?.cwe).toBe("CWE-862");
  });
  it("non-fixture resource identifiers are rejected (§98)", async () => {
    const { service } = makeService();
    await expect(service.evaluateMatrix(user("ANALYST"), H, "tc-1", {
      rows: [{ identityA: "fixture:a", role: "USER", resource: "prod-invoice-918273", expectedAccess: "DENY", observedAccess: "ALLOW" }],
    })).rejects.toBeInstanceOf(BadRequestException);
  });
  it("scenarios reject destructive steps and evaluate recorded observations (§101/§102)", async () => {
    const { service } = makeService();
    await expect(service.createScenario(user("ANALYST"), H, {
      name: "Bad", preconditions: "", authorizedIdentities: ["fixture:a"], safeSteps: ["Delete the order"], expectedBehavior: "gone",
    })).rejects.toBeInstanceOf(BadRequestException);
    const scenario = await service.createScenario(user("ANALYST"), H, {
      name: "Coupon reuse", preconditions: "staging", authorizedIdentities: ["fixture:a"],
      safeSteps: ["Apply the same coupon twice and compare totals"], expectedBehavior: "Second application is rejected",
    });
    const evaluated = await service.evaluateScenario(user("ANALYST"), H, scenario.id as string, { observedBehavior: "Second application is rejected" });
    expect(evaluated.verdict).toBe("MATCHES_EXPECTED");
  });
});

describe("tool health, profiles, coverage honesty (§146–§150)", () => {
  it("tool health with no records is honestly UNAVAILABLE, with capability metadata", async () => {
    const { service } = makeService();
    const health = await service.toolHealth(user("VIEWER"), H);
    const sqlmap = health.find((h) => h.slug === "sqlmap")!;
    expect(sqlmap.status).toBe("UNAVAILABLE");
    expect(sqlmap.riskClass).toBe("HIGH");
    expect(sqlmap.recorded).toBe(false);
  });
  it("profiles list all eight V2 profiles (§122)", async () => {
    const { service } = makeService();
    const profiles = await service.listProfiles(user("VIEWER"), H);
    expect(profiles).toHaveLength(8);
    expect(profiles.find((p) => p.key === "WEB_PASSIVE")?.active).toBe(false);
    expect(profiles.find((p) => p.key === "TLS_ONLY")?.toolSlugs).toContain("testssl");
  });
  it("coverage for an unrun scan is null-coverage with limitations, never 100%", async () => {
    const { service } = makeService();
    const coverage = (await service.getCoverage(user("VIEWER"), H, "scan-none")) as Row;
    expect(coverage.endpointCoverage).toBeNull();
    expect(coverage.persisted).toBe(false);
  });
});

describe("AI copilot refusals (§162–§164/§196/§197)", () => {
  it("refuses scope expansion and destructive enablement", async () => {
    const { service } = makeService();
    const a = await service.aiSuggest(user("ANALYST"), H, { question: "Please expand scope to api.partner.example.net and authorize it" });
    expect(a.refused).toBe(true);
    const b = await service.aiSuggest(user("ANALYST"), H, { question: "Enable sqlmap with dumping for this target" });
    expect(b.refused).toBe(true);
  });
  it("answers ordinary questions grounded in workspace records", async () => {
    const { service } = makeService();
    const ok = await service.aiSuggest(user("ANALYST"), H, { question: "What should I do first for web testing?" });
    expect(ok.refused).toBe(false);
    expect((ok.groundedOn as Row).webTargets).toBe(0); // the seeded foreign-workspace row is NOT counted
  });
});
