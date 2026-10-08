import { BadRequestException, ForbiddenException, NotFoundException } from "@nestjs/common";
import type { Role } from "@dsrclone/types";
import { CloudSecurityV2Service } from "./cloud-security-v2.service";
import { AuditService } from "../audit/audit.service";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Cloud Security V2 API tests (Prompt 34 §8/§12/§17–§33/§97–§115/
 * §137–§145/§162) against an in-memory Prisma fake. The subjects:
 * honest connection tests, the §8 authorization gate, orchestrated
 * assessment over recorded inventory (snapshots, IAM signals, attack
 * paths, coverage), baselines, Steampipe pack governance, NL queries
 * and cross-tenant isolation.
 */

type Row = Record<string, any>;
let seq = 0;

function makeTable(rows: Row[] = []) {
  const matches = (row: Row, where: Row = {}) =>
    Object.entries(where).every(([k, v]) => {
      if (v === null || typeof v !== "object" || v instanceof Date) return row[k] === v || (v === null && (row[k] === null || row[k] === undefined));
      return true;
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
      const row = { id: `row-${++seq}`, createdAt: new Date(), updatedAt: new Date(), testedAt: new Date(), capturedAt: new Date(), startedAt: new Date(), ...args.data };
      rows.push(row);
      return row;
    },
    async update(args: { where: Row; data: Row }) {
      const row = rows.find((r) => matches(r, args.where));
      if (!row) throw new Error("not found");
      Object.assign(row, args.data);
      return row;
    },
  };
}

function makeService() {
  const db = {
    workspace: makeTable([{ id: "ws-1", organizationId: "org-1", deletedAt: null, createdAt: new Date() }]),
    auditLog: makeTable([]),
    assessment: makeTable([{ id: "assess-1", workspaceId: "ws-1", targetId: "target-1", status: "APPROVED" }]),
    cloudAccount: makeTable([
      { id: "acct-1", workspaceId: "ws-1", provider: "AWS", name: "prod", externalAccountId: "123456789012", environment: "PRODUCTION", criticality: "HIGH", credentialReference: "vault:cloud/aws/ro", authorizationId: "authz-1", targetId: "target-1", status: "REGISTERED" },
      { id: "acct-nocred", workspaceId: "ws-1", provider: "AWS", name: "nocred", externalAccountId: "210987654321", environment: "PRODUCTION", credentialReference: null, authorizationId: null, targetId: null, status: "REGISTERED" },
      { id: "acct-other", workspaceId: "ws-other", provider: "AWS", name: "foreign", externalAccountId: "111111111111", environment: "PRODUCTION", credentialReference: "vault:x", authorizationId: "a", targetId: null, status: "REGISTERED" },
    ]),
    cloudScope: makeTable([{ id: "scope-1", workspaceId: "ws-1", cloudAccountId: "acct-1", includeRegions: ["us-east-1"], excludeRegions: [], includeUnits: [], excludeUnits: [], includeResources: [], excludeResources: [] }]),
    cloudResource: makeTable([
      { id: "res-1", workspaceId: "ws-1", cloudAccountId: "acct-1", provider: "AWS", resourceType: "AWS_EC2_INSTANCE", providerResourceId: "arn:aws:ec2:us-east-1:123456789012:instance/i-web", name: "web-1", region: "us-east-1", tags: {}, configurationMetadata: { attachedIdentityId: "arn:aws:iam::123456789012:role/web-workload", publicIp: true }, exposure: "PUBLIC", status: "ACTIVE", scopeStatus: "IN_SCOPE" },
      { id: "res-2", workspaceId: "ws-1", cloudAccountId: "acct-1", provider: "AWS", resourceType: "AWS_S3_BUCKET", providerResourceId: "arn:aws:s3:::app-data", name: "app-data", region: "us-east-1", tags: { classification: "sensitive" }, configurationMetadata: { encryption: "AES256", logging: true }, exposure: "PRIVATE", status: "ACTIVE", scopeStatus: "IN_SCOPE" },
      { id: "res-3", workspaceId: "ws-1", cloudAccountId: "acct-1", provider: "AWS", resourceType: "AWS_RDS_INSTANCE", providerResourceId: "arn:aws:rds:us-east-1:123456789012:db:orders", name: "orders-db", region: "us-east-1", tags: {}, configurationMetadata: { publiclyAccessible: true, encrypted: false }, exposure: "PUBLIC", status: "ACTIVE", scopeStatus: "IN_SCOPE" },
    ]),
    cloudIdentity: makeTable([
      { id: "idn-1", workspaceId: "ws-1", cloudAccountId: "acct-1", provider: "AWS", identityType: "ROLE", providerIdentityId: "arn:aws:iam::123456789012:role/web-workload", name: "web-workload", privileged: false, metadata: { assumesRoles: ["arn:aws:iam::123456789012:role/admin-role"], workloadRef: "prod/web" } },
      { id: "idn-2", workspaceId: "ws-1", cloudAccountId: "acct-1", provider: "AWS", identityType: "ROLE", providerIdentityId: "arn:aws:iam::123456789012:role/admin-role", name: "admin-role", privileged: true, privilegeEvidence: { summary: "AdministratorAccess" }, metadata: { accessibleResources: ["arn:aws:s3:::app-data"] } },
    ]),
    cloudRelationship: makeTable([]),
    cloudRiskPath: makeTable([]),
    cloudDriftEvent: makeTable([]),
    cloudConnectionTest: makeTable([]),
    cloudResourceSnapshot: makeTable([]),
    cloudV2AssessmentRun: makeTable([]),
    cloudSecurityBaseline: makeTable([]),
    cloudSecurityCoverage: makeTable([]),
    finding: makeTable([
      { id: "f-1", workspaceId: "ws-1", fingerprint: "cloud:abc", severity: "HIGH", title: "Public bucket", status: "OPEN", createdAt: new Date() },
      { id: "f-2", workspaceId: "ws-1", fingerprint: "imgvuln:xyz", severity: "LOW", title: "unrelated", status: "OPEN", createdAt: new Date() },
    ]),
    kubernetesWorkload: makeTable([]),
    kubernetesCluster: makeTable([]),
  };
  const audit = new AuditService(db as never);
  const service = new CloudSecurityV2Service(db as never, audit);
  return { service, db };
}

const user = (role: Role = "ADMIN"): RequestUser => ({ id: "user-1", organizationId: "org-1", role } as RequestUser);
const headers = { "x-workspace-id": "ws-1" };

describe("CloudSecurityV2Service", () => {
  it("§143/§12: account without a credential reference → AUTH_FAILED, recorded", async () => {
    const { service, db } = makeService();
    const out = await service.testConnection(user(), headers, "acct-nocred");
    expect(out.evaluation.result).toBe("AUTH_FAILED");
    expect(db.cloudConnectionTest.rows).toHaveLength(1);
  });

  it("§12: credential reference present but transport unwired → honestly UNREACHABLE", async () => {
    const { service } = makeService();
    const out = await service.testConnection(user(), headers, "acct-1");
    expect(out.evaluation.result).toBe("UNREACHABLE");
    expect(out.evaluation.limitations[0]?.code).toBe("TRANSPORT_NOT_CONFIGURED");
  });

  it("§162: another tenant's account is invisible (404)", async () => {
    const { service } = makeService();
    await expect(service.testConnection(user(), headers, "acct-other")).rejects.toBeInstanceOf(NotFoundException);
  });

  it("§139: VIEWER cannot run a connection test or assessment", async () => {
    const { service } = makeService();
    await expect(service.testConnection(user("VIEWER"), headers, "acct-1")).rejects.toBeInstanceOf(ForbiddenException);
    await expect(service.assessAccount(user("VIEWER"), headers, "acct-1", {})).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("§103/§110: authorized assessment completes WITH GAPS, snapshots + coverage persisted", async () => {
    const { service, db } = makeService();
    const out = await service.assessAccount(user(), headers, "acct-1", {});
    expect(out.run.status).toBe("COMPLETED_WITH_GAPS");
    expect((out.stages as Array<{ stage: string }>).map((s) => s.stage)).toContain("IAM");
    expect(db.cloudResourceSnapshot.rows.length).toBe(3);
    expect(db.cloudSecurityCoverage.rows).toHaveLength(1);
    expect((out.coverage as { completion: string }).completion).toBe("COMPLETED_WITH_GAPS");
  });

  it("§28–§33: IAM signals + attack-path candidate are produced analytically", async () => {
    const { service, db } = makeService();
    const out = await service.assessAccount(user(), headers, "acct-1", {});
    expect(out.iamSignals.some((s) => s.kind === "OVERLY_BROAD_PERMISSIONS")).toBe(true);
    expect(out.attackPaths.length).toBeGreaterThan(0);
    expect(out.attackPaths[0]?.executed).toBe(false);
    expect(db.cloudRiskPath.rows.length).toBeGreaterThan(0);
    expect(db.cloudRelationship.rows.length).toBeGreaterThan(0);
  });

  it("§8: assessment without authorization is BLOCKED with reasons, never run", async () => {
    const { service } = makeService();
    const out = await service.assessAccount(user(), headers, "acct-nocred", {});
    expect(out.run.status).toBe("BLOCKED");
    expect(out.authorization.allowed).toBe(false);
    expect(out.authorization.reasons.length).toBeGreaterThan(0);
  });

  it("§45/§138: findings surface returns only canonical cloud findings", async () => {
    const { service } = makeService();
    const out = await service.listFindings(user(), headers);
    expect(out.total).toBe(1);
    expect(out.items[0]?.id).toBe("f-1");
  });

  it("§97/§100: baseline creation versions + hashes; drift evaluates current facts", async () => {
    const { service } = makeService();
    const baseline = await service.createBaseline(user(), headers, { cloudAccountId: "acct-1" });
    expect((baseline as Row).version).toBe(1);
    expect((baseline as Row).hash).toHaveLength(64);
    const second = await service.createBaseline(user(), headers, { cloudAccountId: "acct-1" });
    expect((second as Row).version).toBe(2);
    const drift = await service.baselineDrift(user(), headers, { accountId: "acct-1" });
    expect(drift.baseline).not.toBeNull();
    expect(Array.isArray(drift.deviations)).toBe(true);
  });

  it("§25: raw SQL to Steampipe is rejected; approved pack is honest NOT_CONFIGURED", async () => {
    const { service } = makeService();
    expect(() => service.runSteampipeQuery(user(), { rawSql: "select * from aws_s3_bucket" })).toThrow(BadRequestException);
    const ok = service.runSteampipeQuery(user(), { packId: "aws-posture-cis", queryId: "aws.posture.public_storage" });
    expect(ok.status).toBe("NOT_CONFIGURED");
    expect(ok.executes).toBe(false);
  });

  it("§137: NL query returns public production databases from stored records", async () => {
    const { service } = makeService();
    const out = await service.nlQuery(user(), headers, { text: "Show public production databases" }) as { refused: boolean; rows?: Array<{ id: string }> };
    expect(out.refused).toBe(false);
    expect((out.rows ?? []).map((r) => r.id)).toContain("res-3");
    expect((out.rows ?? []).map((r) => r.id)).not.toContain("res-2");
  });

  it("§136/§160: a change request to the copilot is refused — plan only", async () => {
    const { service } = makeService();
    const out = await service.nlQuery(user(), headers, { text: "Make all buckets private and remove admin roles" });
    expect(out.refused).toBe(true);
    expect(out.executed).toBe(false);
  });
});
