import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import { isValidCredentialReference, looksLikeSecretValue } from "@dsrclone/security-sdk";
import type { RegisterCloudAccountInput, StartCloudScanInput } from "@dsrclone/validation";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { resolveWorkspace } from "../../common/tenant";
import { AuditService } from "../audit/audit.service";
import { OrchestrationService } from "../orchestration/orchestration.service";
import { requireCloudSecurityPermission } from "./permissions";

type Row = Record<string, unknown> & { id: string };

/**
 * Multi-cloud security API (Prompt 14 §87).
 *
 * Discipline carried through every method:
 * - Assessment is READ-ONLY forever (§7): no method creates, modifies
 *   or deletes a cloud resource, and no remediation action exists.
 * - Credentials exist ONLY as secret-reference names (§6) — a value is
 *   never accepted (secret-shaped references are refused), never
 *   stored, never returned and never logged.
 * - Accounts are verified targets (§4): registration records identity;
 *   scans start only through the gated orchestration path (VERIFIED
 *   target + APPROVED assessment + scope), never directly.
 * - Compliance output is control evidence (§84) — never a
 *   certification claim.
 */
@Injectable()
export class CloudSecurityService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly orchestration: OrchestrationService,
  ) {}

  // ── Accounts (§77/§78/§87) ─────────────────────────────────────

  async listAccounts(user: RequestUser) {
    requireCloudSecurityPermission(user, "VIEW_CLOUD_SECURITY");
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.cloudAccount.findMany({
      where: { workspaceId: workspace.id }, orderBy: { createdAt: "desc" }, take: 200,
    });
    const items = [];
    for (const r of rows as unknown as Row[]) {
      const [resources, identities, publicCount] = await Promise.all([
        this.prisma.cloudResource.count({ where: { cloudAccountId: r.id, status: "ACTIVE" } }).catch(() => 0),
        this.prisma.cloudIdentity.count({ where: { cloudAccountId: r.id } }).catch(() => 0),
        this.prisma.cloudResource.count({ where: { cloudAccountId: r.id, exposure: "PUBLIC", status: "ACTIVE" } }).catch(() => 0),
      ]);
      items.push({
        id: r.id, provider: r.provider, name: r.name, externalAccountId: r.externalAccountId,
        environment: r.environment, criticality: r.criticality,
        // Reference NAME + posture only — never a credential value (§6/§78).
        credentialReference: r.credentialReference ?? null,
        credentialConfigured: typeof r.credentialReference === "string" && r.credentialReference.length > 0,
        assessmentPolicy: r.assessmentPolicy, status: r.status,
        lastInventoryAt: r.lastInventoryAt ?? null, lastAssessmentAt: r.lastAssessmentAt ?? null,
        resources, identities, publicResources: publicCount,
      });
    }
    return { items };
  }

  async registerAccount(user: RequestUser, input: RegisterCloudAccountInput) {
    requireCloudSecurityPermission(user, "MANAGE_CLOUD_ACCOUNTS");
    const workspace = await resolveWorkspace(this.prisma, user);
    if (input.credentialReference !== undefined) this.assertReferenceName(input.credentialReference);
    const existing = await this.prisma.cloudAccount.findFirst({
      where: { workspaceId: workspace.id, provider: input.provider as never, externalAccountId: input.externalAccountId },
    });
    if (existing) return { id: (existing as Row).id, status: (existing as Row).status, alreadyRegistered: true };
    const target = await this.prisma.target.create({
      data: {
        workspaceId: workspace.id, name: input.name, type: input.provider as never,
        value: input.externalAccountId, status: "DRAFT", verified: false, createdBy: user.id,
      },
    });
    const account = await this.prisma.cloudAccount.create({
      data: {
        workspaceId: workspace.id, targetId: target.id, provider: input.provider as never,
        name: input.name, externalAccountId: input.externalAccountId,
        environment: input.environment ?? "UNKNOWN", criticality: input.criticality ?? "MEDIUM",
        ...(input.credentialReference ? { credentialReference: input.credentialReference } : {}),
        assessmentPolicy: "READ_ONLY", // §7: the only posture, by design
        status: input.credentialReference ? "REGISTERED" : "NOT_CONFIGURED",
        createdBy: user.id,
      },
    });
    const scope = input.scope ?? {};
    await this.prisma.cloudScope.create({
      data: {
        workspaceId: workspace.id, cloudAccountId: account.id,
        includeRegions: scope.includeRegions ?? [], excludeRegions: scope.excludeRegions ?? [],
        includeUnits: scope.includeUnits ?? [], excludeUnits: scope.excludeUnits ?? [],
        includeResources: scope.includeResources ?? [], excludeResources: scope.excludeResources ?? [],
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "CLOUD_ACCOUNT_REGISTERED", resourceType: "CloudAccount", resourceId: account.id,
      metadata: { provider: input.provider, externalAccountId: input.externalAccountId, credentialConfigured: !!input.credentialReference },
    });
    return { id: account.id, targetId: target.id, provider: input.provider, status: account.status, verified: false };
  }

  private async loadAccount(user: RequestUser, id: string) {
    const workspace = await resolveWorkspace(this.prisma, user);
    const account = await this.prisma.cloudAccount.findFirst({ where: { id, workspaceId: workspace.id } });
    if (!account) throw new NotFoundException("Cloud account not found");
    return { workspace, account: account as unknown as Row & { targetId: string | null; provider: string; externalAccountId: string; credentialReference?: string | null; status: string } };
  }

  async getAccount(user: RequestUser, id: string) {
    requireCloudSecurityPermission(user, "VIEW_CLOUD_SECURITY");
    const { workspace, account } = await this.loadAccount(user, id);
    const [scopes, snapshots, resourcesByExposure, identities, drift, riskPaths] = await Promise.all([
      this.prisma.cloudScope.findMany({ where: { cloudAccountId: id }, take: 10 }),
      this.prisma.cloudInventorySnapshot.findMany({ where: { cloudAccountId: id }, orderBy: { capturedAt: "desc" }, take: 5 }),
      this.prisma.cloudResource.groupBy({ by: ["exposure"], where: { cloudAccountId: id, status: "ACTIVE" }, _count: true }).catch(() => []),
      this.prisma.cloudIdentity.count({ where: { cloudAccountId: id } }).catch(() => 0),
      this.prisma.cloudDriftEvent.count({ where: { cloudAccountId: id } }).catch(() => 0),
      this.prisma.cloudRiskPath.count({ where: { cloudAccountId: id } }).catch(() => 0),
    ]);
    return {
      ...account,
      // The account page NEVER displays credential material (§78):
      // reference name + configured flag only.
      credentialReference: account.credentialReference ?? null,
      credentialConfigured: !!account.credentialReference,
      scopes: (scopes as unknown as Row[]).map((s) => ({
        id: s.id, includeRegions: s.includeRegions, excludeRegions: s.excludeRegions,
        includeUnits: s.includeUnits, excludeUnits: s.excludeUnits,
        includeResources: s.includeResources, excludeResources: s.excludeResources,
      })),
      latestSnapshots: (snapshots as unknown as Row[]).map((s) => ({
        id: s.id, regions: s.regions, resourceCounts: s.resourceCounts, snapshotHash: s.snapshotHash, capturedAt: s.capturedAt,
      })),
      resourcesByExposure: Object.fromEntries((resourcesByExposure as unknown as Array<Record<string, unknown>>).map((g) => [g.exposure as string, (g._count as number) ?? 0])),
      identityCount: identities, driftCount: drift, riskPathCount: riskPaths,
      workspaceId: workspace.id,
    };
  }

  /** POST /cloud/accounts/:id/validate (§87): platform-side credential
   *  posture check. The API never holds a credential value, so this
   *  validates the REFERENCE (§6/§9): missing → NOT_CONFIGURED;
   *  secret-shaped → VALIDATION_FAILED; well-formed → VALIDATED for
   *  scan-time use, where the CLOUD_ANALYSIS worker re-validates the
   *  provider identity under a job-scoped lease (§11) before any
   *  inventory is collected. */
  async validateAccount(user: RequestUser, id: string) {
    requireCloudSecurityPermission(user, "MANAGE_CLOUD_ACCOUNTS");
    const { workspace, account } = await this.loadAccount(user, id);
    let status: string;
    let detail: string;
    if (!account.credentialReference) {
      status = "NOT_CONFIGURED";
      detail = "No credential reference is configured for this account — scans report NOT_CONFIGURED (§9)";
    } else if (!isValidCredentialReference(account.credentialReference) || looksLikeSecretValue(account.credentialReference)) {
      status = "VALIDATION_FAILED";
      detail = "The stored credential reference is not a valid reference name — a secret value must never be stored here (§6)";
    } else {
      status = "VALIDATED";
      detail = "Credential reference accepted; the assessment worker re-validates the provider identity at scan time under a job-scoped lease (§11)";
    }
    await this.prisma.cloudAccount.update({ where: { id }, data: { status } });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "CLOUD_CREDENTIAL_VALIDATED", resourceType: "CloudAccount", resourceId: id,
      metadata: { provider: account.provider, result: status },
    });
    return { accountId: id, status, validated: status === "VALIDATED", detail };
  }

  /** POST /cloud/accounts/:id/scan (§87): records the engagement
   *  approval for this account+profile, then starts through the gated
   *  orchestration path — which re-verifies independently. The target
   *  must be VERIFIED first (§4 discipline, as every target kind). */
  async startAccountScan(user: RequestUser, id: string, input: StartCloudScanInput) {
    requireCloudSecurityPermission(user, "RUN_CLOUD_SCAN");
    const profile = input.profile ?? "CLOUD_BASELINE";
    const { workspace, account } = await this.loadAccount(user, id);
    if (!account.targetId) throw new BadRequestException("cloud account has no target");
    const target = await this.prisma.target.findUnique({ where: { id: account.targetId } });
    if (!target?.verified) throw new BadRequestException("Cloud account target is not VERIFIED — verify the account registration before scanning");
    const started = await this.startGatedScan(user, workspace.id, target as unknown as Row & { id: string; value: string }, account.externalAccountId, profile, "CloudAccount", account.id, "CLOUD_SCAN_STARTED");
    return { accountId: account.id, ...started };
  }

  // ── Resources (§79/§80/§87) ────────────────────────────────────

  async listResources(user: RequestUser, query: { accountId?: string; provider?: string; exposure?: string; resourceType?: string; search?: string }) {
    requireCloudSecurityPermission(user, "VIEW_CLOUD_SECURITY");
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.cloudResource.findMany({
      where: {
        workspaceId: workspace.id,
        ...(query.accountId ? { cloudAccountId: query.accountId } : {}),
        ...(query.provider ? { provider: query.provider as never } : {}),
        ...(query.exposure ? { exposure: query.exposure } : {}),
        ...(query.resourceType ? { resourceType: query.resourceType } : {}),
        ...(query.search ? { name: { contains: query.search, mode: "insensitive" } } : {}),
      },
      orderBy: { lastSeen: "desc" }, take: 500,
    });
    return {
      items: (rows as unknown as Row[]).map((r) => ({
        id: r.id, cloudAccountId: r.cloudAccountId, provider: r.provider, resourceType: r.resourceType,
        providerResourceId: r.providerResourceId, name: r.name, region: r.region ?? null,
        exposure: r.exposure, criticality: r.criticality, status: r.status, scopeStatus: r.scopeStatus,
        sources: r.sources, lastSeen: r.lastSeen,
        // Tags were sanitized at ingestion (§99); listed here as the
        // bounded string map only.
        tags: r.tags,
      })),
    };
  }

  /** GET /cloud/resources/:id (§80): full configuration metadata is a
   *  raw artifact view — OWNER/ADMIN (VIEW_CLOUD_ARTIFACTS) and every
   *  access is audited (§103 CLOUD_ARTIFACT_ACCESSED). */
  async getResource(user: RequestUser, id: string) {
    requireCloudSecurityPermission(user, "VIEW_CLOUD_ARTIFACTS");
    const workspace = await resolveWorkspace(this.prisma, user);
    const resource = await this.prisma.cloudResource.findFirst({ where: { id, workspaceId: workspace.id } });
    if (!resource) throw new NotFoundException("Cloud resource not found");
    const r = resource as unknown as Row;
    const findings = await this.prisma.finding.findMany({
      where: { workspaceId: workspace.id, providerResourceId: r.providerResourceId as string, duplicateOfId: null },
      orderBy: { createdAt: "desc" }, take: 100,
    }).catch(() => []);
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId: workspace.id,
      action: "CLOUD_ARTIFACT_ACCESSED", resourceType: "CloudResource", resourceId: id,
      metadata: { providerResourceId: r.providerResourceId },
    });
    return {
      ...r,
      findings: (findings as unknown as Row[]).map((f) => ({
        id: f.id, title: f.title, severity: f.severity, ruleId: f.ruleId ?? null,
        findingClass: f.findingClass ?? null, status: f.status,
      })),
    };
  }

  // ── IAM (§81/§87) ──────────────────────────────────────────────

  async listIam(user: RequestUser, query: { accountId?: string; provider?: string }) {
    requireCloudSecurityPermission(user, "VIEW_CLOUD_IAM");
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.cloudIdentity.findMany({
      where: {
        workspaceId: workspace.id,
        ...(query.accountId ? { cloudAccountId: query.accountId } : {}),
        ...(query.provider ? { provider: query.provider as never } : {}),
      },
      orderBy: [{ privileged: "desc" }, { name: "asc" }], take: 500,
    });
    return {
      // §40: credential MATERIAL is never part of this view — age and
      // status metadata only; secret values are never retrieved.
      items: (rows as unknown as Row[]).map((i) => ({
        id: i.id, cloudAccountId: i.cloudAccountId, provider: i.provider, identityType: i.identityType,
        providerIdentityId: i.providerIdentityId, name: i.name, privileged: i.privileged,
        privilegeEvidence: i.privilegeEvidence ?? null, mfaEnabled: i.mfaEnabled ?? null,
        lastUsedAt: i.lastUsedAt ?? null, keyAgeDays: i.keyAgeDays ?? null, lastSeen: i.lastSeen,
      })),
    };
  }

  // ── Exposure (§82/§87) ─────────────────────────────────────────

  async listExposure(user: RequestUser) {
    requireCloudSecurityPermission(user, "VIEW_CLOUD_SECURITY");
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.cloudResource.findMany({
      where: { workspaceId: workspace.id, exposure: { in: ["PUBLIC", "INTERNET_REACHABLE_POSSIBLE"] }, status: "ACTIVE" },
      orderBy: { lastSeen: "desc" }, take: 500,
    });
    const findings = await this.prisma.finding.findMany({
      where: { workspaceId: workspace.id, findingClass: "PUBLIC_EXPOSURE", duplicateOfId: null },
      orderBy: { createdAt: "desc" }, take: 500,
    }).catch(() => []);
    return {
      resources: (rows as unknown as Row[]).map((r) => ({
        id: r.id, cloudAccountId: r.cloudAccountId, provider: r.provider, resourceType: r.resourceType,
        providerResourceId: r.providerResourceId, name: r.name, region: r.region ?? null, exposure: r.exposure,
      })),
      exposureFindings: (findings as unknown as Row[]).map((f) => ({
        id: f.id, title: f.title, severity: f.severity, ruleId: f.ruleId ?? null,
        providerResourceId: f.providerResourceId ?? null, cloudRegion: f.cloudRegion ?? null,
      })),
    };
  }

  // ── Drift (§63/§87) ────────────────────────────────────────────

  async listDrift(user: RequestUser, query: { accountId?: string; kind?: string }) {
    requireCloudSecurityPermission(user, "VIEW_CLOUD_SECURITY");
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.cloudDriftEvent.findMany({
      where: {
        workspaceId: workspace.id,
        ...(query.accountId ? { cloudAccountId: query.accountId } : {}),
        ...(query.kind ? { kind: query.kind } : {}),
      },
      orderBy: { detectedAt: "desc" }, take: 500,
    });
    return {
      // §64: a drift event is an observation, never a malicious verdict.
      items: (rows as unknown as Row[]).map((d) => ({
        id: d.id, cloudAccountId: d.cloudAccountId, kind: d.kind, state: d.state ?? null,
        resourceRef: d.resourceRef ?? null, detail: d.detail, detectedAt: d.detectedAt, scanId: d.scanId ?? null,
      })),
    };
  }

  // ── Graph + risk paths (§85/§87) ───────────────────────────────

  async getGraph(user: RequestUser, query: { accountId?: string }) {
    requireCloudSecurityPermission(user, "VIEW_CLOUD_GRAPH");
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.cloudRelationship.findMany({
      where: { workspaceId: workspace.id, ...(query.accountId ? { cloudAccountId: query.accountId } : {}) },
      orderBy: { lastSeen: "desc" }, take: 1000,
    });
    return {
      // §85: edges exist only where a provider response or a governed
      // check supplied evidence — the graph never speculates.
      edges: (rows as unknown as Row[]).map((e) => ({
        id: e.id, cloudAccountId: e.cloudAccountId, fromType: e.fromType, fromRef: e.fromRef,
        toType: e.toType, toRef: e.toRef, relationship: e.relationship, evidence: e.evidence ?? null,
      })),
    };
  }

  async listRiskPaths(user: RequestUser, query: { accountId?: string }) {
    requireCloudSecurityPermission(user, "VIEW_CLOUD_GRAPH");
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.cloudRiskPath.findMany({
      where: { workspaceId: workspace.id, ...(query.accountId ? { cloudAccountId: query.accountId } : {}) },
      orderBy: { createdAt: "desc" }, take: 200,
    });
    return {
      // §67: a risk path is a defensive MODEL of exposure — it is
      // never executed and privilege escalation is never attempted.
      items: (rows as unknown as Row[]).map((p) => ({
        id: p.id, cloudAccountId: p.cloudAccountId, title: p.title, steps: p.steps,
        confidence: p.confidence, findingIds: p.findingIds, createdAt: p.createdAt,
      })),
    };
  }

  // ── Compliance (§84 — reuses the Phase 13 framework) ───────────

  async listCompliance(user: RequestUser, query: { frameworkKey?: string }) {
    requireCloudSecurityPermission(user, "VIEW_CLOUD_COMPLIANCE");
    const workspace = await resolveWorkspace(this.prisma, user);
    const rows = await this.prisma.controlAssessment.findMany({
      where: {
        workspaceId: workspace.id,
        frameworkKey: query.frameworkKey ?? { in: ["CIS_AWS", "CIS_AZURE", "CIS_GCP"] },
      },
      orderBy: { assessedAt: "desc" }, take: 500,
    });
    const byStatus: Record<string, number> = {};
    for (const r of rows as unknown as Row[]) byStatus[r.status as string] = (byStatus[r.status as string] ?? 0) + 1;
    return {
      // §84: posture evidence mapped onto benchmarks/frameworks —
      // NEVER a certification claim.
      disclaimer: "Control assessments are posture evidence from governed checks mapped to CIS benchmarks and framework controls; they are not a compliance certification.",
      byStatus,
      items: (rows as unknown as Row[]).map((r) => ({
        id: r.id, frameworkKey: r.frameworkKey, controlId: r.controlId, subjectRef: r.subjectRef,
        status: r.status, evidence: r.evidence ?? null, assessedAt: r.assessedAt, scanId: r.scanId ?? null,
      })),
    };
  }

  // ── Helpers ────────────────────────────────────────────────────

  private assertReferenceName(reference: string): void {
    if (looksLikeSecretValue(reference) || !isValidCredentialReference(reference)) {
      throw new BadRequestException("credentialReference must be a secret-manager reference NAME — credential values are never accepted or stored (§6)");
    }
  }

  /** Shared gated scan start (mirrors Prompt 13 §91 discipline). */
  private async startGatedScan(
    user: RequestUser,
    workspaceId: string,
    target: Row & { id: string; value: string },
    scopeHost: string,
    profile: string,
    resourceType: string,
    resourceId: string,
    auditAction: string,
  ) {
    const scope = await this.prisma.scope.findFirst({ where: { targetId: target.id } });
    if (!scope) {
      throw new BadRequestException("No pre-existing scope covers this target — create a scope via the scopes flow and request assessment approval via the assessments flow before starting a scan");
    }
    const assessment = await this.prisma.assessment.findFirst({
      where: { targetId: target.id, profile: profile as never, status: "APPROVED", scopeId: (scope as Row).id },
      orderBy: { createdAt: "desc" },
    });
    if (!assessment) {
      throw new BadRequestException("No pre-existing APPROVED assessment covers this target and profile — request approval via the assessments flow before starting a scan");
    }
    const assessmentRow = assessment as unknown as Row;
    if (!assessmentRow.approvedBy || assessmentRow.approvedBy === assessmentRow.createdBy || assessmentRow.approvedBy === user.id) {
      throw new BadRequestException("Assessment approval is not independent — the approver must be neither the assessment creator nor the scan starter; request approval via the assessments flow");
    }
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: auditAction, resourceType, resourceId,
      metadata: { profile, assessmentId: (assessment as Row).id },
    });
    const started = await this.orchestration.startScan(user, (assessment as Row).id);
    return { assessmentId: (assessment as Row).id, ...started };
  }
}
