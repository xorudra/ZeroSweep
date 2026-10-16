import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  buildCycloneDxSbom, buildSpdxSbom, normalizeRepoPath, validateRepositoryUrl,
} from "@dsrclone/security-sdk";
import type {
  CreateRepositoryInput, CreateSourceExclusionInput, StartRepositoryScanInput,
} from "@dsrclone/validation";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { resolveWorkspace } from "../../common/tenant";
import { AuditService } from "../audit/audit.service";
import { OrchestrationService } from "../orchestration/orchestration.service";
import { hasSourcePermission, requireSourcePermission } from "./permissions";

/**
 * Source repository API (Prompt 12 §97). Repositories are first-class
 * targets whose CONTENT IS HOSTILE INPUT (§15): registration validates
 * the reference (SSRF-guarded git URLs, traversal-safe snapshot
 * manifests), credentials exist only as reference names (§9), and
 * nothing here ever executes repository content — scans start through
 * the ordinary gated orchestration path (verified target + approved
 * assessment + scope), and secret data leaves this service as metadata
 * only (§40–§43: type, detector, location, fingerprint, redacted
 * preview — never a value).
 */
@Injectable()
export class RepositoriesService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly orchestration: OrchestrationService,
  ) {}

  private async loadRepository(user: RequestUser, id: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const repo = await this.prisma.sourceRepository.findFirst({ where: { id, workspaceId: workspace.id } });
    if (!repo) throw new NotFoundException("Repository not found");
    return { workspace, repo: repo as unknown as Record<string, unknown> & { id: string; targetId: string | null; name: string } };
  }

  async listRepositories(user: RequestUser) {
    requireSourcePermission(user, "VIEW_SOURCE_REPOSITORIES");
    const workspace = await resolveWorkspace(this.prisma, user);
    const repos = await this.prisma.sourceRepository.findMany({
      where: { workspaceId: workspace.id },
      include: {
        snapshots: { orderBy: { createdAt: "desc" }, take: 1 },
        _count: { select: { snapshots: true, exclusions: true } },
      },
      orderBy: { createdAt: "desc" },
      take: 200,
    });
    const items = [];
    for (const r of repos as unknown as Array<Record<string, unknown>>) {
      const findings = await this.prisma.finding.count({ where: { repositoryId: r.id as string } });
      const secrets = await this.prisma.secretFindingMetadata.count({ where: { finding: { repositoryId: r.id as string } } });
      const latest = (r.snapshots as Array<Record<string, unknown>> | undefined)?.[0];
      items.push({
        id: r.id, name: r.name, sourceKind: r.sourceKind, provider: r.provider ?? null,
        remoteUrl: r.remoteUrl ?? null, defaultBranch: r.defaultBranch ?? null,
        visibility: r.visibility, verified: await this.targetVerified(r.targetId as string | null),
        credentialReference: r.credentialReference ?? null,
        snapshots: ((r._count as { snapshots?: number } | undefined)?.snapshots ?? 0),
        exclusions: ((r._count as { exclusions?: number } | undefined)?.exclusions ?? 0),
        findings, secrets,
        latestSnapshot: latest ? { id: latest.id, hash: latest.snapshotHash, createdAt: latest.createdAt } : null,
        createdAt: r.createdAt,
      });
    }
    return { items };
  }

  private async targetVerified(targetId: string | null): Promise<boolean> {
    if (!targetId) return false;
    const target = await this.prisma.target.findUnique({ where: { id: targetId }, select: { verified: true } });
    return target?.verified ?? false;
  }

  async createRepository(user: RequestUser, input: CreateRepositoryInput) {
    requireSourcePermission(user, "MANAGE_SOURCE_REPOSITORIES");
    const workspace = await resolveWorkspace(this.prisma, user);

    // §7/§8: git remotes pass the SSRF + scheme guards; embedded
    // credentials are rejected outright (references only, §9).
    let targetValue: string;
    if (input.sourceKind === "GIT_REMOTE") {
      if (!input.remoteUrl) throw new BadRequestException("remoteUrl is required for GIT_REMOTE repositories");
      const verdict = validateRepositoryUrl(input.remoteUrl);
      if (!verdict.ok) throw new BadRequestException(`Repository URL rejected: ${verdict.errors.join("; ")}`);
      targetValue = input.remoteUrl;
    } else {
      // Snapshot intakes carry a manifest — every path in it must be a
      // safe repository-relative path (§11 archive discipline applied
      // to the listing itself).
      const manifest = input.snapshotManifest;
      if (!manifest || manifest.files.length === 0) {
        throw new BadRequestException("snapshotManifest with at least one file is required for snapshot repositories");
      }
      for (const f of manifest.files) {
        if (normalizeRepoPath(f.path) === null) throw new BadRequestException(`unsafe path in snapshot manifest: ${f.path}`);
      }
      for (const p of Object.keys(manifest.manifests ?? {})) {
        if (normalizeRepoPath(p) === null) throw new BadRequestException(`unsafe manifest path: ${p}`);
      }
      targetValue = input.name;
    }

    const target = await this.prisma.target.create({
      data: {
        workspaceId: workspace.id, name: input.name, type: "SOURCE_REPOSITORY",
        value: targetValue, status: "DRAFT", verified: false, createdBy: user.id,
      },
    });
    const repo = await this.prisma.sourceRepository.create({
      data: {
        organizationId: user.organizationId, workspaceId: workspace.id, targetId: target.id,
        name: input.name, provider: input.provider, remoteUrl: input.remoteUrl,
        defaultBranch: input.defaultBranch, visibility: input.visibility ?? "PRIVATE",
        sourceKind: input.sourceKind as never,
        credentialReference: input.credentialReference,
        snapshotManifest: (input.snapshotManifest ?? undefined) as never,
        createdBy: user.id,
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "SOURCE_REPOSITORY_CREATED", resourceType: "SourceRepository", resourceId: repo.id,
      metadata: { sourceKind: input.sourceKind },
    });
    return { id: repo.id, targetId: target.id, name: repo.name, sourceKind: repo.sourceKind, verified: false };
  }

  async getRepository(user: RequestUser, id: string) {
    requireSourcePermission(user, "VIEW_SOURCE_REPOSITORIES");
    const { repo } = await this.loadRepository(user, id);
    const findings = await this.prisma.finding.groupBy({
      by: ["severity"], where: { repositoryId: id }, _count: { _all: true },
    }).catch(() => []);
    const secrets = await this.prisma.secretFindingMetadata.count({ where: { finding: { repositoryId: id } } });
    const snapshots = await this.prisma.sourceSnapshot.findMany({
      where: { repositoryId: id }, orderBy: { createdAt: "desc" }, take: 20,
    });
    return {
      ...repo,
      credentialReference: repo.credentialReference ?? null,
      snapshotManifest: undefined, // raw manifest content is artifact-gated (§98)
      verified: await this.targetVerified(repo.targetId),
      findingsBySeverity: (findings as Array<{ severity: string; _count: { _all: number } }>).map((g) => ({ severity: g.severity, count: g._count._all })),
      secrets,
      snapshots: (snapshots as unknown as Array<Record<string, unknown>>).map((s) => ({
        id: s.id, hash: s.snapshotHash, commitSha: s.commitSha ?? null, branch: s.branch ?? null,
        fileCount: s.fileCount, sourceKind: s.sourceKind, scanId: s.scanId ?? null, createdAt: s.createdAt,
        languages: s.languages ?? [], frameworks: s.frameworks ?? [], buildSystems: s.buildSystems ?? [],
      })),
    };
  }

  /** Verification requires real ownership proof — never a bare URL
   *  re-validation by the registrant. Either a DNS_TXT / HTTP_FILE
   *  challenge for the repository target has already completed through
   *  the targets module, or an OWNER/ADMIN other than the registrant
   *  records a manual approval on the registration evidence. Only then
   *  is the target marked VERIFIED. */
  async verifyRepository(user: RequestUser, id: string) {
    requireSourcePermission(user, "MANAGE_SOURCE_REPOSITORIES");
    const { workspace, repo } = await this.loadRepository(user, id);
    if (!repo.targetId) throw new BadRequestException("repository has no target to verify");
    if (repo.sourceKind === "GIT_REMOTE") {
      const verdict = validateRepositoryUrl((repo.remoteUrl as string) ?? "");
      if (!verdict.ok) throw new BadRequestException(`Repository URL no longer passes intake guards: ${verdict.errors.join("; ")}`);
    } else {
      const manifest = repo.snapshotManifest as { files?: unknown[] } | null;
      if (!manifest || !Array.isArray(manifest.files) || manifest.files.length === 0) {
        throw new BadRequestException("snapshot repository has no registered manifest to verify");
      }
    }
    const target = await this.prisma.target.findUnique({ where: { id: repo.targetId } });
    const challengeProof = await this.prisma.targetVerification.findFirst({
      where: { targetId: repo.targetId, status: "VERIFIED" },
    });
    const hasChallengeProof = !!challengeProof
      && ((challengeProof as unknown as Record<string, unknown>).method === "DNS_TXT"
        || (challengeProof as unknown as Record<string, unknown>).method === "HTTP_FILE");
    if (!hasChallengeProof) {
      // Manual path: the approver must be independent of the registrant.
      const registrantIds = new Set([repo.createdBy as string | undefined, (target as unknown as Record<string, unknown> | null)?.createdBy as string | undefined]);
      const isIndependentApprover = (user.role === "OWNER" || user.role === "ADMIN") && !registrantIds.has(user.id);
      if (!isIndependentApprover) {
        throw new BadRequestException(
          "Repository verification requires a completed DNS_TXT or HTTP_FILE ownership challenge via the targets module, or manual approval by an OWNER/ADMIN other than the registrant",
        );
      }
      await this.prisma.targetVerification.create({
        data: {
          targetId: repo.targetId, method: "MANUAL_APPROVAL", challenge: "repository-registration-review",
          status: "VERIFIED", verifiedAt: new Date(),
        },
      });
    }
    await this.prisma.target.update({ where: { id: repo.targetId }, data: { verified: true, status: "VERIFIED" } });
    void workspace;
    return { id: repo.id, verified: true };
  }

  /** POST /repositories/:id/scans (§97): consumes — never mints —
   *  governance records. The scan starts only against a pre-existing
   *  scope and a pre-existing APPROVED assessment whose approver is
   *  neither its creator nor the scan starter; approval is requested
   *  through the governed assessments flow. Orchestration then
   *  re-verifies target + approval + scope independently (§4). */
  async startScan(user: RequestUser, id: string, input: StartRepositoryScanInput) {
    requireSourcePermission(user, "RUN_SOURCE_SCAN");
    const profile = input.profile ?? "SOURCE_BASELINE";
    const { workspace, repo } = await this.loadRepository(user, id);
    if (!repo.targetId) throw new BadRequestException("repository has no target");
    const target = await this.prisma.target.findUnique({ where: { id: repo.targetId } });
    if (!target?.verified) throw new BadRequestException("Repository target is not VERIFIED — verify the repository before scanning (§4)");

    const scope = await this.prisma.scope.findFirst({ where: { targetId: target.id } });
    if (!scope) {
      throw new BadRequestException("No pre-existing scope covers this repository target — create a scope via the scopes flow and request assessment approval via the assessments flow before starting a scan");
    }
    const assessment = await this.prisma.assessment.findFirst({
      where: { targetId: target.id, profile: profile as never, status: "APPROVED", scopeId: scope.id },
      orderBy: { createdAt: "desc" },
    });
    if (!assessment) {
      throw new BadRequestException("No pre-existing APPROVED assessment covers this repository target and profile — request approval via the assessments flow before starting a scan");
    }
    const assessmentRow = assessment as unknown as Record<string, unknown>;
    if (!assessmentRow.approvedBy || assessmentRow.approvedBy === assessmentRow.createdBy || assessmentRow.approvedBy === user.id) {
      throw new BadRequestException("Assessment approval is not independent — the approver must be neither the assessment creator nor the scan starter; request approval via the assessments flow");
    }
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "SOURCE_SCAN_REQUESTED", resourceType: "SourceRepository", resourceId: repo.id,
      metadata: { profile, assessmentId: assessment.id },
    });
    const started = await this.orchestration.startScan(user, assessment.id);
    return { repositoryId: repo.id, assessmentId: assessment.id, ...started };
  }

  async listSnapshots(user: RequestUser, id: string) {
    requireSourcePermission(user, "VIEW_SOURCE_REPOSITORIES");
    await this.loadRepository(user, id);
    const rows = await this.prisma.sourceSnapshot.findMany({
      where: { repositoryId: id }, orderBy: { createdAt: "desc" }, take: 100,
    });
    return {
      items: (rows as unknown as Array<Record<string, unknown>>).map((s) => ({
        id: s.id, hash: s.snapshotHash, commitSha: s.commitSha ?? null, branch: s.branch ?? null,
        fileCount: s.fileCount, totalSizeBytes: s.totalSizeBytes != null ? String(s.totalSizeBytes) : "0",
        sourceKind: s.sourceKind, scanId: s.scanId ?? null, createdAt: s.createdAt,
        languages: s.languages ?? [], frameworks: s.frameworks ?? [], buildSystems: s.buildSystems ?? [],
      })),
    };
  }

  async listFindings(user: RequestUser, id: string, query: { page: number; pageSize: number }) {
    requireSourcePermission(user, "VIEW_CODE_FINDINGS");
    await this.loadRepository(user, id);
    const canSeeSecrets = hasSourcePermission(user, "VIEW_SECRET_METADATA");
    const [total, rows] = await Promise.all([
      this.prisma.finding.count({ where: { repositoryId: id } }),
      this.prisma.finding.findMany({
        where: { repositoryId: id },
        include: { secretMetadata: true },
        orderBy: { createdAt: "desc" },
        skip: (query.page - 1) * query.pageSize,
        take: query.pageSize,
      }),
    ]);
    const items = (rows as unknown as Array<Record<string, unknown>>).map((f) => {
      const secret = f.secretMetadata as Record<string, unknown> | null;
      return {
        id: f.id, title: f.title, severity: f.severity, status: f.status,
        lifecycleStatus: f.lifecycleStatus, confidence: f.confidence,
        filePath: f.filePath ?? null, startLine: f.startLine ?? null, endLine: f.endLine ?? null,
        ruleId: f.ruleId ?? null, cwe: f.cwe ?? null, cve: f.cve ?? null,
        componentPurl: f.componentPurl ?? null, fixedVersion: f.fixedVersion ?? null,
        reachability: f.reachability ?? null, baselineStatus: f.baselineStatus ?? null,
        reviewStatus: f.reviewStatus ?? null, sources: f.sources ?? [],
        scanId: f.scanId, snapshotId: f.snapshotId ?? null, createdAt: f.createdAt,
        // Metadata only, and only for secret-permitted roles (§98).
        secret: secret && canSeeSecrets ? {
          secretType: secret.secretType, detector: secret.detector,
          fingerprint: secret.fingerprint, redactedPreview: secret.redactedPreview ?? null,
          verificationStatus: secret.verificationStatus, lifecycleStatus: secret.lifecycleStatus,
        } : undefined,
      };
    });
    return { items, total, page: query.page, pageSize: query.pageSize };
  }

  /** §93 secret dashboard data: metadata rows ONLY. There is no code
   *  path in this service that can return a secret value — none is
   *  stored anywhere (§40). */
  async listSecrets(user: RequestUser, id: string) {
    requireSourcePermission(user, "VIEW_SECRET_METADATA");
    await this.loadRepository(user, id);
    const rows = await this.prisma.secretFindingMetadata.findMany({
      where: { finding: { repositoryId: id } },
      include: { finding: { select: { id: true, title: true, severity: true, status: true, scanId: true } } },
      orderBy: { firstSeenAt: "desc" },
      take: 500,
    });
    const items = (rows as unknown as Array<Record<string, unknown>>).map((s) => {
      const finding = s.finding as Record<string, unknown>;
      return {
        id: s.id, findingId: s.findingId, title: finding.title, severity: finding.severity,
        findingStatus: finding.status, scanId: finding.scanId,
        secretType: s.secretType, detector: s.detector,
        filePath: s.filePath ?? null, startLine: s.startLine ?? null,
        commitSha: s.commitSha ?? null, fingerprint: s.fingerprint,
        redactedPreview: s.redactedPreview ?? null,
        verificationStatus: s.verificationStatus, lifecycleStatus: s.lifecycleStatus,
        firstSeenAt: s.firstSeenAt, lastSeenAt: s.lastSeenAt,
      };
    });
    const byType: Record<string, number> = {};
    const byLifecycle: Record<string, number> = {};
    for (const i of items) {
      byType[i.secretType as string] = (byType[i.secretType as string] ?? 0) + 1;
      byLifecycle[i.lifecycleStatus as string] = (byLifecycle[i.lifecycleStatus as string] ?? 0) + 1;
    }
    return { items, total: items.length, byType, byLifecycle };
  }

  async updateSecretLifecycle(user: RequestUser, id: string, secretId: string, lifecycleStatus: string) {
    requireSourcePermission(user, "MANAGE_SOURCE_REPOSITORIES");
    const { workspace, repo } = await this.loadRepository(user, id);
    const row = await this.prisma.secretFindingMetadata.findFirst({
      where: { id: secretId, finding: { repositoryId: id } },
    });
    if (!row) throw new NotFoundException("Secret finding not found");
    const updated = await this.prisma.secretFindingMetadata.update({
      where: { id: secretId }, data: { lifecycleStatus: lifecycleStatus as never },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "SOURCE_FINDING_RESOLVED", resourceType: "SecretFindingMetadata", resourceId: secretId,
      metadata: { repositoryId: repo.id, lifecycleStatus },
    });
    return { id: updated.id, lifecycleStatus: updated.lifecycleStatus };
  }

  /** §94 dependency dashboard: the LATEST snapshot's inventory with
   *  per-component finding counts from the scan pipeline. */
  async listDependencies(user: RequestUser, id: string) {
    requireSourcePermission(user, "VIEW_CODE_FINDINGS");
    await this.loadRepository(user, id);
    const snapshot = await this.prisma.sourceSnapshot.findFirst({
      where: { repositoryId: id }, orderBy: { createdAt: "desc" },
    });
    if (!snapshot) return { snapshot: null, items: [], total: 0, byEcosystem: {} };
    const components = await this.prisma.softwareComponent.findMany({
      where: { snapshotId: snapshot.id }, orderBy: [{ ecosystem: "asc" }, { name: "asc" }], take: 2000,
    });
    const findings = await this.prisma.finding.findMany({
      where: { repositoryId: id, snapshotId: snapshot.id, componentPurl: { not: null } },
      select: { componentPurl: true, severity: true, cve: true, fixedVersion: true, reachability: true },
    });
    const byPurl = new Map<string, Array<Record<string, unknown>>>();
    for (const f of findings as unknown as Array<Record<string, unknown>>) {
      const list = byPurl.get(f.componentPurl as string) ?? [];
      list.push(f);
      byPurl.set(f.componentPurl as string, list);
    }
    const byEcosystem: Record<string, number> = {};
    const items = (components as unknown as Array<Record<string, unknown>>).map((c) => {
      byEcosystem[c.ecosystem as string] = (byEcosystem[c.ecosystem as string] ?? 0) + 1;
      const vulns = byPurl.get(c.purl as string) ?? [];
      return {
        id: c.id, name: c.name, version: c.version ?? null, ecosystem: c.ecosystem, purl: c.purl,
        sourceManifest: c.sourceManifest, scope: c.scope, dependencyScope: c.dependencyScope,
        licenses: c.licenses ?? [], supplier: c.supplier ?? null,
        vulnerabilities: vulns.map((v) => ({ cve: v.cve, severity: v.severity, fixedVersion: v.fixedVersion ?? null, reachability: v.reachability ?? null })),
      };
    });
    return { snapshot: { id: snapshot.id, hash: snapshot.snapshotHash, createdAt: snapshot.createdAt }, items, total: items.length, byEcosystem };
  }

  /** §95 SBOM view + export: metadata from the SBOM rows; the document
   *  is REBUILT deterministically from the snapshot's component rows
   *  (documents are artifacts, never database blobs, §47). */
  async getSbom(user: RequestUser, id: string, format: "CYCLONEDX_JSON" | "SPDX_TAG_VALUE" = "CYCLONEDX_JSON") {
    requireSourcePermission(user, "EXPORT_SBOM");
    const { repo } = await this.loadRepository(user, id);
    const snapshot = await this.prisma.sourceSnapshot.findFirst({
      where: { repositoryId: id }, orderBy: { createdAt: "desc" },
    });
    if (!snapshot) throw new NotFoundException("No snapshot exists for this repository yet");
    const rows = await this.prisma.softwareBillOfMaterials.findMany({ where: { snapshotId: snapshot.id } });
    const components = await this.prisma.softwareComponent.findMany({ where: { snapshotId: snapshot.id } });
    const normalized = (components as unknown as Array<Record<string, unknown>>).map((c) => ({
      name: c.name as string, version: (c.version as string | null) ?? undefined,
      ecosystem: c.ecosystem as string, purl: c.purl as string,
      sourceManifest: c.sourceManifest as string, scope: c.scope as never,
      dependencyScope: c.dependencyScope as never, licenses: (c.licenses as string[]) ?? [],
      ...((c.supplier as string | null) ? { supplier: c.supplier as string } : {}),
    }));
    const built = format === "SPDX_TAG_VALUE"
      ? buildSpdxSbom(normalized, { snapshotHash: snapshot.snapshotHash, repositoryName: repo.name, timestamp: new Date().toISOString() })
      : buildCycloneDxSbom(normalized, { snapshotHash: snapshot.snapshotHash, repositoryName: repo.name, timestamp: new Date().toISOString() });
    return {
      snapshotId: snapshot.id,
      records: (rows as unknown as Array<Record<string, unknown>>).map((r) => ({
        id: r.id, format: r.format, specVersion: r.specVersion, checksum: r.checksum,
        artifactRef: r.artifactRef ?? null, componentCount: r.componentCount, createdAt: r.createdAt,
      })),
      document: { format: built.sbom.format, specVersion: built.sbom.specVersion, checksum: built.sbom.checksum, componentCount: built.sbom.componentCount, content: built.document },
    };
  }

  /** GET /source-scans/:id/quality-gate (§97): the recorded verdict for
   *  a source scan — PASSED / FAILED / WARNING with rule detail (§82). */
  async getQualityGate(user: RequestUser, scanId: string) {
    requireSourcePermission(user, "VIEW_CODE_FINDINGS");
    const workspace = await resolveWorkspace(this.prisma, user);
    const scan = await this.prisma.scan.findFirst({ where: { id: scanId, workspaceId: workspace.id } });
    if (!scan) throw new NotFoundException("Scan not found");
    const result = await this.prisma.qualityGateResult.findFirst({
      where: { scanId }, orderBy: { evaluatedAt: "desc" },
    });
    if (!result) throw new NotFoundException("No quality gate result recorded for this scan");
    const r = result as unknown as Record<string, unknown>;
    return {
      scanId, snapshotId: r.snapshotId ?? null, status: r.status,
      policyVersion: r.policyVersion, failedRules: r.failedRules ?? [],
      warningRules: r.warningRules ?? [], summary: r.summary ?? {},
      evaluatedAt: r.evaluatedAt,
    };
  }

  /** Raw snapshot manifest access (§98): OWNER/ADMIN only, ALWAYS
   *  audited as SOURCE_ARTIFACT_ACCESSED (§110). Returns the registered
   *  manifest data — file listing + manifest file contents. */
  async getSnapshotManifest(user: RequestUser, id: string) {
    requireSourcePermission(user, "VIEW_RAW_SOURCE_ARTIFACTS");
    const { workspace, repo } = await this.loadRepository(user, id);
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "SOURCE_ARTIFACT_ACCESSED", resourceType: "SourceRepository", resourceId: repo.id,
      metadata: { kind: "SNAPSHOT_MANIFEST" },
    });
    return { repositoryId: repo.id, snapshotManifest: repo.snapshotManifest ?? null };
  }

  async createExclusion(user: RequestUser, id: string, input: CreateSourceExclusionInput) {
    requireSourcePermission(user, "MANAGE_SOURCE_POLICIES");
    const { workspace, repo } = await this.loadRepository(user, id);
    const row = await this.prisma.sourceScanExclusion.create({
      data: {
        repositoryId: repo.id, exclusionType: input.exclusionType,
        pattern: input.pattern, reason: input.reason, createdBy: user.id,
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "SOURCE_ARTIFACT_ACCESSED", resourceType: "SourceScanExclusion", resourceId: row.id,
      metadata: { kind: "EXCLUSION_CREATED", exclusionType: input.exclusionType },
    });
    return { id: row.id, repositoryId: repo.id, exclusionType: row.exclusionType, pattern: row.pattern };
  }
}
