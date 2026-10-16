import { BadRequestException, ForbiddenException, NotFoundException } from "@nestjs/common";
import { RepositoriesService } from "./repositories.service";

/**
 * Prompt 12 §97–§109 API discipline: repositories are tenant-isolated,
 * git intake is SSRF-guarded, credentials are reference names only,
 * scan start is gated on a VERIFIED target, secret surfaces return
 * metadata only (never a value), and raw manifest access is
 * OWNER/ADMIN + audited.
 */

const owner = { id: "u-1", email: "r@example.com", organizationId: "org-1", role: "OWNER" as const };
const viewer = { id: "u-3", email: "v@example.com", organizationId: "org-1", role: "VIEWER" as const };
const foreign = { id: "u-2", email: "x@example.com", organizationId: "org-2", role: "OWNER" as const };

const WORKSPACES = [
  { id: "ws-1", organizationId: "org-1", deletedAt: null, createdAt: new Date(0) },
  { id: "ws-2", organizationId: "org-2", deletedAt: null, createdAt: new Date(0) },
];

interface State {
  targets: Array<Record<string, unknown>>;
  repos: Array<Record<string, unknown>>;
  snapshots: Array<Record<string, unknown>>;
  findings: Array<Record<string, unknown>>;
  secrets: Array<Record<string, unknown>>;
  components: Array<Record<string, unknown>>;
  sboms: Array<Record<string, unknown>>;
  qualityGates: Array<Record<string, unknown>>;
  scans: Array<Record<string, unknown>>;
  audits: Array<Record<string, unknown>>;
  verifications: Array<Record<string, unknown>>;
  scopes: Array<Record<string, unknown>>;
  assessments: Array<Record<string, unknown>>;
  exclusions: Array<Record<string, unknown>>;
}

function freshState(): State {
  return {
    targets: [{ id: "t-1", workspaceId: "ws-1", name: "fixture-repo", type: "SOURCE_REPOSITORY", value: "fixture-repo", verified: false, status: "DRAFT" }],
    repos: [{
      id: "repo-1", organizationId: "org-1", workspaceId: "ws-1", targetId: "t-1", name: "fixture-repo",
      sourceKind: "LOCAL_SOURCE_SNAPSHOT", remoteUrl: null, provider: null, defaultBranch: "main",
      visibility: "PRIVATE", credentialReference: null,
      snapshotManifest: { files: [{ path: "src/app.py", sizeBytes: 120 }], manifests: { "requirements.txt": "flask==1.1.2\n" } },
      createdAt: new Date(0), snapshots: [], _count: { snapshots: 1, exclusions: 0 },
    }],
    snapshots: [{
      id: "snap-1", repositoryId: "repo-1", scanId: "scan-1", snapshotHash: "abc123", commitSha: "deadbeef",
      branch: "main", fileCount: 1, totalSizeBytes: 120n, sourceKind: "LOCAL_SOURCE_SNAPSHOT",
      languages: [{ language: "Python", files: 1, share: 1 }], frameworks: [], buildSystems: [], createdAt: new Date(0),
    }],
    findings: [{
      id: "f-1", repositoryId: "repo-1", workspaceId: "ws-1", scanId: "scan-1", snapshotId: "snap-1",
      title: "Possible shell command execution", severity: "HIGH", status: "OPEN", lifecycleStatus: "NEW",
      confidence: 0.8, filePath: "src/app.py", startLine: 8, endLine: 8, ruleId: "python.lang.security.audit.subprocess-shell-true",
      cwe: "CWE-78", cve: null, componentPurl: null, fixedVersion: null, reachability: null,
      baselineStatus: "NEW", reviewStatus: null, sources: ["semgrep"], createdAt: new Date(0), secretMetadata: null,
    }],
    secrets: [{
      id: "sec-1", findingId: "f-2", secretType: "CLOUD_CREDENTIAL", detector: "aws-access-token",
      filePath: "config/aws-credentials.txt", startLine: 2, commitSha: null, fingerprint: "hmac-sha256:xyz",
      redactedPreview: "AKIA…MPLE", verificationStatus: "NOT_VERIFIED", lifecycleStatus: "OPEN",
      firstSeenAt: new Date(0), lastSeenAt: new Date(0),
      finding: { id: "f-2", repositoryId: "repo-1", title: "AWS access key detected", severity: "CRITICAL", status: "OPEN", scanId: "scan-1" },
    }],
    components: [{
      id: "c-1", snapshotId: "snap-1", name: "flask", version: "1.1.2", ecosystem: "pypi",
      purl: "pkg:pypi/flask@1.1.2", sourceManifest: "requirements.txt", scope: "DIRECT",
      dependencyScope: "RUNTIME", licenses: ["BSD-3-Clause"], supplier: null,
    }],
    sboms: [{ id: "sbom-1", snapshotId: "snap-1", scanId: "scan-1", format: "CYCLONEDX_JSON", specVersion: "1.5", checksum: "deadbeef", artifactRef: "sbom://snap-1/deadbeef", componentCount: 1, createdAt: new Date(0) }],
    qualityGates: [{ scanId: "scan-1", snapshotId: "snap-1", status: "FAILED", policyVersion: "1.0.0", failedRules: ["NO_CRITICAL_SECRETS"], warningRules: [], summary: {}, evaluatedAt: new Date(0) }],
    scans: [{ id: "scan-1", workspaceId: "ws-1" }],
    audits: [], verifications: [], scopes: [], assessments: [], exclusions: [],
  };
}

function fakePrisma(state: State) {
  const byId = (rows: Array<Record<string, unknown>>) => async (args: { where?: Record<string, unknown> }) =>
    rows.find((r) => Object.entries(args.where ?? {}).every(([k, v]) => v === undefined || r[k] === v)) ?? null;
  const byWhere = (rows: Array<Record<string, unknown>>) => async (args: { where?: Record<string, unknown> }) =>
    rows.filter((r) => Object.entries(args.where ?? {}).every(([k, v]) => {
      if (v === undefined) return true;
      if (typeof v === "object" && v !== null) {
        if ("not" in (v as Record<string, unknown>)) return r[k] !== null && r[k] !== undefined;
        const nested = v as Record<string, unknown>;
        const target = r[k] as Record<string, unknown> | null;
        return target != null && Object.entries(nested).every(([nk, nv]) => target[nk] === nv);
      }
      return r[k] === v;
    }));
  return {
    workspace: { findFirst: byId(WORKSPACES as unknown as Array<Record<string, unknown>>) },
    sourceRepository: {
      findFirst: byId(state.repos), findMany: byWhere(state.repos),
      create: async (args: { data: Record<string, unknown> }) => { const row = { id: "repo-new", ...args.data }; state.repos.push(row); return row; },
    },
    target: {
      findFirst: byId(state.targets), findUnique: byId(state.targets),
      create: async (args: { data: Record<string, unknown> }) => { const row = { id: "t-new", ...args.data }; state.targets.push(row); return row; },
      update: async (args: { where: { id: string }; data: Record<string, unknown> }) => {
        const row = state.targets.find((t) => t.id === args.where.id)!;
        Object.assign(row, args.data); return row;
      },
    },
    targetVerification: {
      create: async (args: { data: Record<string, unknown> }) => { state.verifications.push(args.data); return args.data; },
      findFirst: byId(state.verifications),
    },
    scope: { findFirst: byId(state.scopes), create: async (args: { data: Record<string, unknown> }) => { const row = { id: "scope-1", ...args.data }; state.scopes.push(row); return row; } },
    assessment: {
      findFirst: byId(state.assessments),
      create: async (args: { data: Record<string, unknown> }) => { const row = { id: "as-1", ...args.data }; state.assessments.push(row); return row; },
    },
    sourceSnapshot: { findFirst: byId(state.snapshots), findMany: async () => state.snapshots },
    finding: {
      count: async (args: { where?: Record<string, unknown> }) => (await byWhere(state.findings)(args)).length,
      findMany: byWhere(state.findings),
      groupBy: async () => [{ severity: "HIGH", _count: { _all: 1 } }],
    },
    secretFindingMetadata: {
      count: async () => state.secrets.length,
      findMany: async () => state.secrets,
      findFirst: byId(state.secrets),
      update: async (args: { where: { id: string }; data: Record<string, unknown> }) => {
        const row = state.secrets.find((s) => s.id === args.where.id)!;
        Object.assign(row, args.data); return row;
      },
    },
    softwareComponent: { findMany: async () => state.components },
    softwareBillOfMaterials: { findMany: async () => state.sboms },
    qualityGateResult: { findFirst: byId(state.qualityGates) },
    scan: { findFirst: byId(state.scans) },
    sourceScanExclusion: { create: async (args: { data: Record<string, unknown> }) => { const row = { id: "ex-1", ...args.data }; state.exclusions.push(row); return row; } },
    auditLog: { create: async (args: { data: Record<string, unknown> }) => { state.audits.push(args.data); return args.data; } },
  };
}

function makeService(state: State) {
  const prisma = fakePrisma(state);
  const audit = { record: async (entry: Record<string, unknown>) => { state.audits.push(entry); } };
  const started: string[] = [];
  const orchestration = { startScan: async (_user: unknown, assessmentId: string) => { started.push(assessmentId); return { scanId: "scan-9", status: "QUEUED" }; } };
  const service = new RepositoriesService(prisma as never, audit as never, orchestration as never);
  return { service, started };
}

describe("RepositoriesService (Prompt 12 §97–§109)", () => {
  it("lists repositories tenant-scoped; a foreign org sees none of ours (§109)", async () => {
    const state = freshState();
    const { service } = makeService(state);
    const mine = await service.listRepositories(owner);
    expect(mine.items.map((i) => i.id)).toContain("repo-1");
    const theirs = await service.listRepositories(foreign);
    expect(theirs.items).toHaveLength(0);
  });

  it("foreign repository ids are 404, never a leak (§109)", async () => {
    const state = freshState();
    const { service } = makeService(state);
    await expect(service.getRepository(foreign, "repo-1")).rejects.toBeInstanceOf(NotFoundException);
    await expect(service.listSecrets(foreign, "repo-1")).rejects.toBeInstanceOf(NotFoundException);
  });

  it("rejects SSRF git URLs and credential-embedded URLs at intake (§7/§8)", async () => {
    const state = freshState();
    const { service } = makeService(state);
    await expect(service.createRepository(owner, {
      name: "evil", sourceKind: "GIT_REMOTE", remoteUrl: "https://169.254.169.254/latest/meta-data",
    })).rejects.toBeInstanceOf(BadRequestException);
    await expect(service.createRepository(owner, {
      name: "evil2", sourceKind: "GIT_REMOTE", remoteUrl: "https://user:pass@github.com/example/repo.git",
    })).rejects.toBeInstanceOf(BadRequestException);
  });

  it("rejects traversal paths in snapshot manifests (§11)", async () => {
    const state = freshState();
    const { service } = makeService(state);
    await expect(service.createRepository(owner, {
      name: "evil3", sourceKind: "LOCAL_SOURCE_SNAPSHOT",
      snapshotManifest: { files: [{ path: "../escape.txt", sizeBytes: 1 }], manifests: {} },
    })).rejects.toBeInstanceOf(BadRequestException);
  });

  it("scan start is refused until the target is VERIFIED (§4), then consumes a pre-existing independently-approved assessment", async () => {
    const state = freshState();
    const { service, started } = makeService(state);
    await expect(service.startScan(owner, "repo-1", { profile: "SOURCE_BASELINE" })).rejects.toBeInstanceOf(BadRequestException);
    await service.verifyRepository(owner, "repo-1");
    // Governance records must pre-exist: a scope plus an APPROVED
    // assessment approved by someone other than its creator and the
    // scan starter — startScan must never mint either one.
    state.scopes.push({ id: "scope-1", workspaceId: "ws-1", targetId: "t-1", name: "repo scope", rules: {} });
    state.assessments.push({
      id: "as-1", workspaceId: "ws-1", targetId: "t-1", scopeId: "scope-1", profile: "SOURCE_BASELINE",
      status: "APPROVED", createdBy: "u-creator", approvedBy: "u-approver",
    });
    const result = await service.startScan(owner, "repo-1", { profile: "SOURCE_BASELINE" });
    expect(result.scanId).toBe("scan-9");
    expect(started).toEqual(["as-1"]);
    expect(state.audits.some((a) => a.action === "SOURCE_SCAN_REQUESTED")).toBe(true);
    expect(state.scopes).toHaveLength(1);
    expect(state.assessments).toHaveLength(1);
  });

  it("scan start refuses when no pre-existing scope or APPROVED assessment exists — and mints neither", async () => {
    const state = freshState();
    const { service, started } = makeService(state);
    await service.verifyRepository(owner, "repo-1");
    await expect(service.startScan(owner, "repo-1", { profile: "SOURCE_BASELINE" })).rejects.toBeInstanceOf(BadRequestException);
    state.scopes.push({ id: "scope-1", workspaceId: "ws-1", targetId: "t-1", name: "repo scope", rules: {} });
    await expect(service.startScan(owner, "repo-1", { profile: "SOURCE_BASELINE" })).rejects.toBeInstanceOf(BadRequestException);
    expect(started).toEqual([]);
    expect(state.assessments).toHaveLength(0);
  });

  it("scan start refuses a self-approved assessment (approver == creator or == starter)", async () => {
    const state = freshState();
    const { service, started } = makeService(state);
    await service.verifyRepository(owner, "repo-1");
    state.scopes.push({ id: "scope-1", workspaceId: "ws-1", targetId: "t-1", name: "repo scope", rules: {} });
    state.assessments.push({
      id: "as-self", workspaceId: "ws-1", targetId: "t-1", scopeId: "scope-1", profile: "SOURCE_BASELINE",
      status: "APPROVED", createdBy: "u-creator", approvedBy: "u-creator",
    });
    await expect(service.startScan(owner, "repo-1", { profile: "SOURCE_BASELINE" })).rejects.toBeInstanceOf(BadRequestException);
    state.assessments[0] = { ...state.assessments[0], createdBy: "u-creator", approvedBy: owner.id };
    await expect(service.startScan(owner, "repo-1", { profile: "SOURCE_BASELINE" })).rejects.toBeInstanceOf(BadRequestException);
    expect(started).toEqual([]);
  });

  it("verify refuses registrant self-verification; an independent OWNER approves, or a completed DNS challenge proves ownership", async () => {
    const engineer = { id: "u-se", email: "se@example.com", organizationId: "org-1", role: "SECURITY_ENGINEER" as const };
    const state = freshState();
    (state.repos[0] as Record<string, unknown>).createdBy = "u-se";
    (state.targets[0] as Record<string, unknown>).createdBy = "u-se";
    const { service } = makeService(state);
    // The registrant (even with MANAGE permission) cannot self-verify.
    await expect(service.verifyRepository(engineer, "repo-1")).rejects.toBeInstanceOf(BadRequestException);
    expect(state.verifications).toHaveLength(0);
    expect(state.targets[0]?.verified).toBe(false);
    // A completed DNS_TXT challenge is real proof — no manual row minted.
    state.verifications.push({ targetId: "t-1", method: "DNS_TXT", challenge: "dsrclone-verify=x", status: "VERIFIED" });
    const out = await service.verifyRepository(engineer, "repo-1");
    expect(out.verified).toBe(true);
    expect(state.verifications).toHaveLength(1);
  });

  it("verify via manual approval requires OWNER/ADMIN other than the registrant", async () => {
    const engineer = { id: "u-se", email: "se@example.com", organizationId: "org-1", role: "SECURITY_ENGINEER" as const };
    const state = freshState();
    (state.repos[0] as Record<string, unknown>).createdBy = "u-se";
    (state.targets[0] as Record<string, unknown>).createdBy = "u-se";
    const { service } = makeService(state);
    await expect(service.verifyRepository(engineer, "repo-1")).rejects.toBeInstanceOf(BadRequestException);
    const out = await service.verifyRepository(owner, "repo-1");
    expect(out.verified).toBe(true);
    expect(state.verifications.some((v) => v.method === "MANUAL_APPROVAL" && v.status === "VERIFIED")).toBe(true);
  });

  it("secret surfaces return metadata only — no value-shaped field exists (§40/§101)", async () => {
    const state = freshState();
    const { service } = makeService(state);
    const secrets = await service.listSecrets(owner, "repo-1");
    expect(secrets.items[0]?.redactedPreview).toBe("AKIA…MPLE");
    expect(secrets.items[0]?.fingerprint).toBe("hmac-sha256:xyz");
    const serialized = JSON.stringify(secrets);
    expect(serialized).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(Object.keys(secrets.items[0] ?? {})).not.toContain("value");
    expect(Object.keys(secrets.items[0] ?? {})).not.toContain("secret");
  });

  it("VIEWER cannot see secret metadata, manage repositories, or read raw manifests (§98)", async () => {
    const state = freshState();
    const { service } = makeService(state);
    await expect(service.listSecrets(viewer, "repo-1")).rejects.toBeInstanceOf(ForbiddenException);
    await expect(service.createRepository(viewer, { name: "x", sourceKind: "LOCAL_SOURCE_SNAPSHOT", snapshotManifest: { files: [{ path: "a.py", sizeBytes: 1 }] } })).rejects.toBeInstanceOf(ForbiddenException);
    await expect(service.getSnapshotManifest(viewer, "repo-1")).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("raw manifest access is audited as SOURCE_ARTIFACT_ACCESSED (§110)", async () => {
    const state = freshState();
    const { service } = makeService(state);
    const out = await service.getSnapshotManifest(owner, "repo-1");
    expect(out.snapshotManifest).not.toBeNull();
    expect(state.audits.some((a) => a.action === "SOURCE_ARTIFACT_ACCESSED")).toBe(true);
  });

  it("quality gate endpoint returns the recorded verdict; unknown scans 404 (§82/§97)", async () => {
    const state = freshState();
    const { service } = makeService(state);
    const gate = await service.getQualityGate(owner, "scan-1");
    expect(gate.status).toBe("FAILED");
    expect(gate.failedRules).toContain("NO_CRITICAL_SECRETS");
    await expect(service.getQualityGate(owner, "scan-nope")).rejects.toBeInstanceOf(NotFoundException);
    await expect(service.getQualityGate(foreign, "scan-1")).rejects.toBeInstanceOf(NotFoundException);
  });

  it("dependencies + SBOM come from the latest snapshot's rows (§94/§95)", async () => {
    const state = freshState();
    const { service } = makeService(state);
    const deps = await service.listDependencies(owner, "repo-1");
    expect(deps.items.map((i) => i.name)).toContain("flask");
    const sbom = await service.getSbom(owner, "repo-1");
    expect(sbom.document.format).toBe("CYCLONEDX_JSON");
    expect(sbom.document.content).toContain("flask");
    expect(sbom.records[0]?.checksum).toBe("deadbeef");
  });
});
