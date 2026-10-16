import { BadRequestException, ForbiddenException, NotFoundException } from "@nestjs/common";
import { CloudSecurityService } from "./cloud-security.service";

/**
 * Prompt 14 §87–§103 API discipline: accounts are tenant-isolated;
 * credentials are reference names only (a secret-shaped value is
 * refused and never stored); validation is honest about what the API
 * can check (§9); scan starts are gated on a VERIFIED target; raw
 * resource configuration access is OWNER/ADMIN and audited (§103);
 * compliance output never claims certification (§84).
 */

const owner = { id: "u-1", email: "r@example.com", organizationId: "org-1", role: "OWNER" as const };
const analyst = { id: "u-4", email: "a@example.com", organizationId: "org-1", role: "ANALYST" as const };
const viewer = { id: "u-3", email: "v@example.com", organizationId: "org-1", role: "VIEWER" as const };
const foreign = { id: "u-2", email: "x@example.com", organizationId: "org-2", role: "OWNER" as const };

interface State {
  targets: Array<Record<string, unknown>>;
  accounts: Array<Record<string, unknown>>;
  cloudScopes: Array<Record<string, unknown>>;
  resources: Array<Record<string, unknown>>;
  identities: Array<Record<string, unknown>>;
  snapshots: Array<Record<string, unknown>>;
  drift: Array<Record<string, unknown>>;
  riskPaths: Array<Record<string, unknown>>;
  relationships: Array<Record<string, unknown>>;
  assessments: Array<Record<string, unknown>>;
  findings: Array<Record<string, unknown>>;
  scopes: Array<Record<string, unknown>>;
  engagements: Array<Record<string, unknown>>;
  audits: Array<Record<string, unknown>>;
}

function freshState(): State {
  return {
    targets: [
      { id: "t-aws", workspaceId: "ws-1", name: "prod-aws", type: "AWS", value: "123456789012", verified: true, status: "VERIFIED" },
    ],
    accounts: [{
      id: "acct-1", workspaceId: "ws-1", targetId: "t-aws", provider: "AWS", name: "prod-aws",
      externalAccountId: "123456789012", environment: "PRODUCTION", criticality: "HIGH",
      credentialReference: "vault:prod/aws/assessment-role", assessmentPolicy: "READ_ONLY",
      status: "REGISTERED", lastInventoryAt: null, lastAssessmentAt: null, createdAt: new Date(0),
    }],
    cloudScopes: [{
      id: "cs-1", workspaceId: "ws-1", cloudAccountId: "acct-1", includeRegions: ["us-east-1"], excludeRegions: [],
      includeUnits: [], excludeUnits: [], includeResources: [], excludeResources: [],
    }],
    resources: [{
      id: "res-1", workspaceId: "ws-1", cloudAccountId: "acct-1", provider: "AWS", resourceType: "AWS_S3_BUCKET",
      providerResourceId: "arn:aws:s3:::public-assets-fixture", name: "public-assets-fixture", region: "us-east-1",
      tags: { DataClass: "public" }, configurationMetadata: { publicAccess: true }, exposure: "PUBLIC",
      criticality: "UNSPECIFIED", status: "ACTIVE", scopeStatus: "IN_SCOPE", sources: ["aws-inventory"], lastSeen: new Date(0),
    }],
    identities: [{
      id: "idn-1", workspaceId: "ws-1", cloudAccountId: "acct-1", provider: "AWS", identityType: "USER",
      providerIdentityId: "arn:aws:iam::123456789012:user/rudra-admin-fixture", name: "rudra-admin-fixture",
      privileged: true, privilegeEvidence: { adminEquivalent: true }, mfaEnabled: false, lastUsedAt: null, keyAgeDays: 540, lastSeen: new Date(0),
    }],
    snapshots: [], drift: [{
      id: "dr-1", workspaceId: "ws-1", cloudAccountId: "acct-1", kind: "LOGGING_CHANGED", state: null,
      resourceRef: "main-trail", detail: "audit logging changed", detectedAt: new Date(0), scanId: "scan-1",
    }],
    riskPaths: [{
      id: "rp-1", workspaceId: "ws-1", cloudAccountId: "acct-1", title: "Public bucket path", steps: [],
      confidence: "HIGH", findingIds: [], createdAt: new Date(0),
    }],
    relationships: [{
      id: "rel-1", workspaceId: "ws-1", cloudAccountId: "acct-1", fromType: "IDENTITY", fromRef: "WebRole",
      toType: "RESOURCE", toRef: "arn:aws:s3:::public-assets-fixture", relationship: "GRANTS", evidence: "policy", lastSeen: new Date(0),
    }],
    assessments: [{
      id: "ca-1", workspaceId: "ws-1", frameworkKey: "CIS_AWS", controlId: "2.1.2", subjectRef: "arn:aws:s3:::public-assets-fixture",
      status: "FAIL", evidence: "public access", assessedAt: new Date(0), scanId: "scan-1",
    }],
    findings: [], scopes: [], engagements: [], audits: [],
  };
}

const WORKSPACES = [
  { id: "ws-1", organizationId: "org-1", deletedAt: null, createdAt: new Date(0) },
  { id: "ws-2", organizationId: "org-2", deletedAt: null, createdAt: new Date(0) },
];

let seq = 100;
function fakePrisma(state: State) {
  const matchValue = (actual: unknown, expected: unknown): boolean => {
    if (expected === undefined) return true;
    if (expected !== null && typeof expected === "object") {
      const e = expected as Record<string, unknown>;
      if (Array.isArray(e.in)) return e.in.includes(actual);
      if (typeof e.contains === "string") return typeof actual === "string" && actual.toLowerCase().includes((e.contains as string).toLowerCase());
    }
    return actual === expected;
  };
  const match = (row: Record<string, unknown>, where: Record<string, unknown> = {}) =>
    Object.entries(where).every(([k, v]) => matchValue(row[k], v));
  const model = (rows: Array<Record<string, unknown>>, prefix: string) => ({
    findMany: async (args: { where?: Record<string, unknown> } = {}) => rows.filter((r) => match(r, args.where)),
    findFirst: async (args: { where?: Record<string, unknown> } = {}) => rows.find((r) => match(r, args.where)) ?? null,
    findUnique: async (args: { where: { id: string } }) => rows.find((r) => r.id === args.where.id) ?? null,
    count: async (args: { where?: Record<string, unknown> } = {}) => rows.filter((r) => match(r, args.where)).length,
    create: async (args: { data: Record<string, unknown> }) => {
      const row = { id: `${prefix}-${++seq}`, createdAt: new Date(0), ...args.data };
      rows.push(row);
      return row;
    },
    update: async (args: { where: { id: string }; data: Record<string, unknown> }) => {
      const row = rows.find((r) => r.id === args.where.id);
      if (row) Object.assign(row, args.data);
      return row;
    },
    groupBy: async (args: { by: string[]; where?: Record<string, unknown> }) => {
      const key = args.by[0]!;
      const groups = new Map<unknown, number>();
      for (const r of rows.filter((x) => match(x, args.where))) groups.set(r[key], (groups.get(r[key]) ?? 0) + 1);
      return [...groups.entries()].map(([v, c]) => ({ [key]: v, _count: c }));
    },
  });
  return {
    workspace: {
      findFirst: async (args: { where: { organizationId: string } }) =>
        WORKSPACES.find((w) => w.organizationId === args.where.organizationId) ?? null,
    },
    target: model(state.targets, "t"),
    cloudAccount: model(state.accounts, "acct"),
    cloudScope: model(state.cloudScopes, "cs"),
    cloudResource: model(state.resources, "res"),
    cloudIdentity: model(state.identities, "idn"),
    cloudInventorySnapshot: model(state.snapshots, "snap"),
    cloudDriftEvent: model(state.drift, "dr"),
    cloudRiskPath: model(state.riskPaths, "rp"),
    cloudRelationship: model(state.relationships, "rel"),
    controlAssessment: model(state.assessments, "ca"),
    finding: model(state.findings, "f"),
    scope: model(state.scopes, "scp"),
    assessment: model(state.engagements, "asm"),
  };
}

function makeService(state: State) {
  const prisma = fakePrisma(state);
  const audit = { record: async (e: Record<string, unknown>) => { state.audits.push(e); } };
  const orchestration = { startScan: async () => ({ scanId: "scan-1", status: "QUEUED" }) };
  return new CloudSecurityService(prisma as never, audit as never, orchestration as never);
}

describe("Prompt 14 API — accounts", () => {
  it("registers an account as target + account + scope and audits it (§4/§87/§103)", async () => {
    const state = freshState();
    const svc = makeService(state);
    const out = await svc.registerAccount(owner, {
      name: "staging-gcp", provider: "GCP", externalAccountId: "staging-project-1",
      credentialReference: "vault:staging/gcp/assessment-role", environment: "STAGING", criticality: "MEDIUM",
      scope: { includeRegions: ["us-central1"], excludeRegions: [], includeUnits: [], excludeUnits: [], includeResources: [], excludeResources: [] },
    });
    expect(out.verified).toBe(false);
    expect(out.status).toBe("REGISTERED");
    const target = state.targets.find((t) => t.id === out.targetId)!;
    expect(target.type).toBe("GCP");
    const account = state.accounts.find((a) => a.id === out.id)!;
    expect(account.assessmentPolicy).toBe("READ_ONLY");
    expect(state.cloudScopes.some((s) => s.cloudAccountId === out.id)).toBe(true);
    expect(state.audits.some((a) => a.action === "CLOUD_ACCOUNT_REGISTERED")).toBe(true);
  });

  it("refuses a credential VALUE where a reference name belongs (§6)", async () => {
    const svc = makeService(freshState());
    await expect(svc.registerAccount(owner, {
      name: "bad", provider: "AWS", externalAccountId: "123456789012",
      credentialReference: "AKIAIOSFODNN7EXAMPLE",
    })).rejects.toBeInstanceOf(BadRequestException);
    await expect(svc.registerAccount(viewer, {
      name: "bad", provider: "AWS", externalAccountId: "123456789012",
    })).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("an account without a credential reference registers as NOT_CONFIGURED (§9)", async () => {
    const state = freshState();
    const svc = makeService(state);
    const out = await svc.registerAccount(owner, { name: "no-creds", provider: "AZURE", externalAccountId: "sub-9" });
    expect(out.status).toBe("NOT_CONFIGURED");
  });

  it("validate: well-formed reference → VALIDATED; missing reference → NOT_CONFIGURED (§9)", async () => {
    const state = freshState();
    const svc = makeService(state);
    const ok = await svc.validateAccount(owner, "acct-1");
    expect(ok.status).toBe("VALIDATED");
    expect(state.accounts[0]?.status).toBe("VALIDATED");
    expect(state.audits.some((a) => a.action === "CLOUD_CREDENTIAL_VALIDATED")).toBe(true);

    (state.accounts[0] as Record<string, unknown>).credentialReference = null;
    const missing = await svc.validateAccount(owner, "acct-1");
    expect(missing.status).toBe("NOT_CONFIGURED");
    expect(missing.validated).toBe(false);
  });

  it("is tenant-isolated: foreign org cannot see the account (§102)", async () => {
    const svc = makeService(freshState());
    await expect(svc.getAccount(foreign, "acct-1")).rejects.toBeInstanceOf(NotFoundException);
    const list = await svc.listAccounts(foreign);
    expect(list.items).toHaveLength(0);
  });

  it("scan start is gated on a VERIFIED account target (§4)", async () => {
    const state = freshState();
    const svc = makeService(state);
    state.scopes.push({ id: "scp-1", workspaceId: "ws-1", targetId: "t-aws", name: "cloud scope", rules: {} });
    state.engagements.push({
      id: "asm-1", workspaceId: "ws-1", targetId: "t-aws", scopeId: "scp-1", profile: "CLOUD_BASELINE",
      status: "APPROVED", createdBy: "u-creator", approvedBy: "u-approver",
    });
    const out = await svc.startAccountScan(owner, "acct-1", {});
    expect(out.scanId).toBe("scan-1");
    expect(state.scopes).toHaveLength(1);
    expect(state.engagements).toHaveLength(1);
    expect(state.audits.some((a) => a.action === "CLOUD_SCAN_STARTED")).toBe(true);
    (state.targets[0] as Record<string, unknown>).verified = false;
    await expect(svc.startAccountScan(owner, "acct-1", {})).rejects.toBeInstanceOf(BadRequestException);
    await expect(svc.startAccountScan(viewer, "acct-1", {})).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("scan start refuses when no pre-approved assessment exists — and mints neither scope nor assessment", async () => {
    const state = freshState();
    const svc = makeService(state);
    await expect(svc.startAccountScan(owner, "acct-1", {})).rejects.toBeInstanceOf(BadRequestException);
    expect(state.scopes).toHaveLength(0);
    expect(state.engagements).toHaveLength(0);
  });

  it("account views expose the reference NAME only — never a credential value (§78)", async () => {
    const svc = makeService(freshState());
    const detail = await svc.getAccount(owner, "acct-1");
    expect(detail.credentialReference).toBe("vault:prod/aws/assessment-role");
    expect(detail.credentialConfigured).toBe(true);
    expect(JSON.stringify(detail)).not.toContain("secretKey");
  });
});

describe("Prompt 14 API — resources, IAM, exposure, drift, graph, compliance", () => {
  it("lists resources and IAM identities with privilege metadata only (§79/§81)", async () => {
    const svc = makeService(freshState());
    const resources = await svc.listResources(owner, {});
    expect(resources.items).toHaveLength(1);
    expect(resources.items[0]?.exposure).toBe("PUBLIC");
    const iam = await svc.listIam(analyst, {});
    expect(iam.items[0]?.privileged).toBe(true);
    expect(iam.items[0]?.keyAgeDays).toBe(540);
    expect(JSON.stringify(iam)).not.toContain("accessKeyValue");
    await expect(svc.listIam(viewer, {})).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("raw resource detail is OWNER/ADMIN-only and audited per access (§80/§103)", async () => {
    const state = freshState();
    const svc = makeService(state);
    await expect(svc.getResource(analyst, "res-1")).rejects.toBeInstanceOf(ForbiddenException);
    const detail = await svc.getResource(owner, "res-1");
    expect((detail as Record<string, unknown>).providerResourceId).toBe("arn:aws:s3:::public-assets-fixture");
    expect(state.audits.some((a) => a.action === "CLOUD_ARTIFACT_ACCESSED")).toBe(true);
  });

  it("exposure, drift, risk paths and graph read from persisted evidence (§82/§85)", async () => {
    const svc = makeService(freshState());
    const exposure = await svc.listExposure(owner);
    expect(exposure.resources).toHaveLength(1);
    const drift = await svc.listDrift(owner, {});
    expect(drift.items[0]?.kind).toBe("LOGGING_CHANGED");
    const paths = await svc.listRiskPaths(owner, {});
    expect(paths.items).toHaveLength(1);
    const graph = await svc.getGraph(owner, {});
    expect(graph.edges[0]?.relationship).toBe("GRANTS");
  });

  it("compliance output carries the no-certification disclaimer (§84)", async () => {
    const svc = makeService(freshState());
    const out = await svc.listCompliance(owner, {});
    expect(out.disclaimer).toContain("not a compliance certification");
    expect(out.byStatus.FAIL).toBe(1);
  });
});
