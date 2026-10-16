import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  GRC_DISCLAIMER, buildPackageManifest, hashEvidence, redactForPackage, verifyPackage,
} from "../grc-helpers";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { AuditService as PlatformAuditService } from "../../audit/audit.service";
import { requireGrcPermission } from "../permissions";
import type {
  CreateAuditFindingInput, CreateAuditInput, CreateEvidenceRequestInput,
  GrantAuditorAccessInput, SubmitEvidenceRequestInput,
} from "../dto/schemas";

/**
 * Audit management (Prompt 26 §64–§75). Audit findings are separate
 * from technical findings (§69/§70 — linked by reference only).
 * Evidence packages (§71–§73) are CONFIDENTIAL by default, built from
 * the assessment's snapshot results + APPROVED evidence, redacted
 * through the platform redaction discipline, and sealed with a hash
 * manifest whose verification fails on any tampering (§133).
 * Auditor access (§74/§75) is explicit-share, time-limited grants.
 */
@Injectable()
export class GrcAuditService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: PlatformAuditService,
  ) {}

  async createAudit(user: RequestUser, workspaceId: string, input: CreateAuditInput) {
    requireGrcPermission(user, "MANAGE_AUDITS");
    const row = await this.prisma.auditEngagement.create({
      data: {
        workspaceId, frameworkId: input.frameworkId ?? null, assessmentId: input.assessmentId ?? null,
        type: input.type, auditorRef: input.auditorRef ?? "", scope: (input.scope ?? {}) as never,
        periodStart: input.periodStart ? new Date(input.periodStart) : null,
        periodEnd: input.periodEnd ? new Date(input.periodEnd) : null,
        status: "PLANNED", createdBy: user.id,
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "AUDIT_CREATED", resourceType: "AuditEngagement", resourceId: row.id,
      metadata: { type: input.type },
    });
    return row;
  }

  async listAudits(user: RequestUser, workspaceId: string) {
    requireGrcPermission(user, "VIEW_AUDITS");
    const items = await this.prisma.auditEngagement.findMany({
      where: { workspaceId }, orderBy: { createdAt: "desc" },
    });
    const enriched = [];
    for (const a of items) {
      const requests = await this.prisma.auditEvidenceRequest.findMany({ where: { workspaceId, auditId: a.id } });
      const findings = await this.prisma.auditFinding.findMany({ where: { workspaceId, auditId: a.id } });
      const packages = await this.prisma.auditEvidencePackage.findMany({ where: { workspaceId, auditId: a.id } });
      enriched.push({
        ...a,
        openRequests: requests.filter((r) => ["OPEN", "IN_PROGRESS", "OVERDUE"].includes(r.status)).length,
        openFindings: findings.filter((f) => f.status === "OPEN" || f.status === "IN_REMEDIATION").length,
        packageCount: packages.length,
      });
    }
    return { items: enriched, total: enriched.length };
  }

  private async mustFindAudit(workspaceId: string, id: string) {
    const row = await this.prisma.auditEngagement.findFirst({ where: { id, workspaceId } });
    if (!row) throw new NotFoundException("Audit engagement not found in this workspace");
    return row;
  }

  /* --------------------------- evidence requests --------------------------- */

  async createRequest(user: RequestUser, workspaceId: string, auditId: string, input: CreateEvidenceRequestInput) {
    requireGrcPermission(user, "MANAGE_AUDITS");
    await this.mustFindAudit(workspaceId, auditId);
    return this.prisma.auditEvidenceRequest.create({
      data: {
        workspaceId, auditId, title: input.title, controlId: input.controlId ?? null,
        requirementId: input.requirementId ?? null, ownerId: input.ownerId,
        dueDate: input.dueDate ? new Date(input.dueDate) : null, status: "OPEN",
      },
    });
  }

  async submitRequest(user: RequestUser, workspaceId: string, auditId: string, requestId: string, input: SubmitEvidenceRequestInput) {
    requireGrcPermission(user, "VIEW_AUDITS");
    await this.mustFindAudit(workspaceId, auditId);
    const request = await this.prisma.auditEvidenceRequest.findFirst({ where: { id: requestId, workspaceId, auditId } });
    if (!request) throw new NotFoundException("Evidence request not found");
    for (const evidenceId of input.evidenceIds) {
      const ev = await this.prisma.complianceEvidence.findFirst({ where: { id: evidenceId, workspaceId } });
      if (!ev) throw new BadRequestException(`Evidence ${evidenceId} does not exist in this workspace`);
    }
    const updated = await this.prisma.auditEvidenceRequest.update({
      where: { id: requestId }, data: { status: "SUBMITTED", evidenceIds: input.evidenceIds },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "AUDIT_EVIDENCE_SUBMITTED", resourceType: "AuditEvidenceRequest", resourceId: requestId,
      metadata: { auditId, evidenceCount: input.evidenceIds.length },
    });
    return updated;
  }

  async decideRequest(user: RequestUser, workspaceId: string, auditId: string, requestId: string, decision: "ACCEPTED" | "REJECTED") {
    requireGrcPermission(user, "REVIEW_AUDIT_EVIDENCE");
    await this.mustFindAudit(workspaceId, auditId);
    const request = await this.prisma.auditEvidenceRequest.findFirst({ where: { id: requestId, workspaceId, auditId } });
    if (!request) throw new NotFoundException("Evidence request not found");
    if (request.ownerId === user.id && decision === "ACCEPTED") {
      throw new BadRequestException("Segregation of duties: the request owner cannot accept their own submitted evidence (§111)");
    }
    const updated = await this.prisma.auditEvidenceRequest.update({ where: { id: requestId }, data: { status: decision } });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "AUDIT_EVIDENCE_ACCEPTED", resourceType: "AuditEvidenceRequest", resourceId: requestId,
      metadata: { auditId, decision },
    });
    return updated;
  }

  /* ------------------------------ audit findings ----------------------------- */

  async createFinding(user: RequestUser, workspaceId: string, auditId: string, input: CreateAuditFindingInput) {
    requireGrcPermission(user, "MANAGE_AUDITS");
    await this.mustFindAudit(workspaceId, auditId);
    // §70: linked technical findings are verified to exist but are
    // NEVER merged into this record.
    for (const findingId of input.linkedFindingIds ?? []) {
      const f = await this.prisma.finding.findFirst({ where: { id: findingId, workspaceId } });
      if (!f) throw new BadRequestException(`Technical finding ${findingId} does not exist in this workspace`);
    }
    const row = await this.prisma.auditFinding.create({
      data: {
        workspaceId, auditId, title: input.title, description: input.description ?? "",
        severity: input.severity ?? "MEDIUM", requirementId: input.requirementId ?? null,
        ownerId: input.ownerId, dueDate: input.dueDate ? new Date(input.dueDate) : null,
        status: "OPEN", linkedFindingIds: input.linkedFindingIds ?? [],
      },
    });
    return row;
  }

  async listFindings(user: RequestUser, workspaceId: string, auditId: string) {
    requireGrcPermission(user, "VIEW_AUDITS");
    await this.mustFindAudit(workspaceId, auditId);
    const items = await this.prisma.auditFinding.findMany({
      where: { workspaceId, auditId }, orderBy: { createdAt: "desc" },
    });
    return { items, total: items.length };
  }

  /* -------------------------------- packages -------------------------------- */

  /** §71–§73: build the package from the assessment snapshot results
   *  + approved evidence, redact every content string, seal with the
   *  SDK manifest. The bundle is stored so integrity can be verified
   *  at any later time (§133). */
  async generatePackage(user: RequestUser, workspaceId: string, auditId: string, assessmentId: string) {
    requireGrcPermission(user, "GENERATE_AUDIT_PACKAGE");
    const engagement = await this.mustFindAudit(workspaceId, auditId);
    const assessment = await this.prisma.complianceAssessment.findFirst({ where: { id: assessmentId, workspaceId } });
    if (!assessment) throw new NotFoundException("Assessment not found in this workspace");
    const results = await this.prisma.assessmentRequirementResult.findMany({
      where: { workspaceId, assessmentId }, orderBy: { createdAt: "asc" },
    });
    const evidenceIds = [...new Set(results.flatMap((r) => (r.evidenceIds as string[]) ?? []))];
    const files: Array<{ path: string; content: string; sourceRef: string; classification: string }> = [];
    const bundle: Record<string, string> = {};
    const addFile = (path: string, content: unknown, sourceRef: string, classification: string) => {
      const text = redactForPackage(typeof content === "string" ? content : JSON.stringify(content, null, 2));
      files.push({ path, content: text, sourceRef, classification });
      bundle[path] = text;
    };
    addFile("assessment.json", {
      id: assessment.id, name: assessment.name, frameworkKey: assessment.frameworkKey,
      frameworkVersion: assessment.frameworkVersion, status: assessment.status,
      periodStart: assessment.periodStart, periodEnd: assessment.periodEnd,
      disclaimer: GRC_DISCLAIMER,
    }, `assessment:${assessment.id}`, "CONFIDENTIAL");
    addFile("control-results.json", results.map((r) => ({
      requirementId: r.requirementId, result: r.result, reviewStatus: r.reviewStatus,
      controlIds: r.controlIds, evidenceIds: r.evidenceIds, exceptionIds: r.exceptionIds,
    })), `assessment:${assessment.id}:results`, "CONFIDENTIAL");
    for (const evidenceId of evidenceIds) {
      const ev = await this.prisma.complianceEvidence.findFirst({ where: { id: evidenceId, workspaceId } });
      if (!ev) continue;
      if (ev.reviewStatus !== "NOT_REQUIRED" && ev.reviewStatus !== "APPROVED") continue; // approved evidence only (§71)
      addFile(`evidence/${ev.id}.json`, {
        id: ev.id, controlId: ev.controlId, sourceType: ev.sourceType, sourceId: ev.sourceId,
        classification: ev.classification, collectedAt: ev.collectedAt, hash: ev.hash, snapshot: ev.snapshot,
      }, `evidence:${ev.id}`, ev.classification);
    }
    const exceptions = await this.prisma.riskException.findMany({ where: { workspaceId }, take: 200 });
    addFile("risk-exceptions.json", exceptions.map((e) => ({
      id: e.id, findingId: e.findingId, type: e.type, status: e.status, expiresAt: e.expiresAt,
    })), "risk-exceptions", "CONFIDENTIAL");
    const generatedAt = new Date().toISOString();
    const packageId = `pkg-${assessment.id.slice(0, 8)}-${Date.now()}`;
    const manifest = buildPackageManifest({
      packageId, assessmentId: assessment.id, frameworkKey: assessment.frameworkKey,
      frameworkVersion: assessment.frameworkVersion, generatedAt, files,
    });
    const row = await this.prisma.auditEvidencePackage.create({
      data: {
        workspaceId, auditId, assessmentId, frameworkKey: assessment.frameworkKey,
        frameworkVersion: assessment.frameworkVersion, classification: "CONFIDENTIAL",
        manifest: manifest as never, manifestHash: manifest.manifestHash, bundle,
        generatedBy: user.id,
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "AUDIT_PACKAGE_GENERATED", resourceType: "AuditEvidencePackage", resourceId: row.id,
      metadata: { auditId, assessmentId, manifestHash: manifest.manifestHash, files: files.length },
    });
    return { ...row, engagementType: engagement.type };
  }

  /** §133: recompute every hash in the stored bundle against the manifest. */
  async verifyPackageIntegrity(user: RequestUser, workspaceId: string, packageId: string) {
    requireGrcPermission(user, "VIEW_AUDITS");
    const row = await this.prisma.auditEvidencePackage.findFirst({ where: { id: packageId, workspaceId } });
    if (!row) throw new NotFoundException("Package not found in this workspace");
    const contents = new Map(Object.entries(row.bundle as Record<string, string>));
    const verification = verifyPackage(row.manifest as never, contents);
    return { packageId, manifestHash: row.manifestHash, ...verification };
  }

  async downloadPackage(user: RequestUser, workspaceId: string, packageId: string) {
    requireGrcPermission(user, "GENERATE_AUDIT_PACKAGE");
    const row = await this.prisma.auditEvidencePackage.findFirst({ where: { id: packageId, workspaceId } });
    if (!row) throw new NotFoundException("Package not found in this workspace");
    // §73: temporary download — every download is counted + audited.
    const updated = await this.prisma.auditEvidencePackage.update({
      where: { id: packageId },
      data: { downloadCount: (row.downloadCount ?? 0) + 1, lastDownloadAt: new Date() },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "AUDIT_PACKAGE_GENERATED", resourceType: "AuditEvidencePackage", resourceId: packageId,
      metadata: { download: true, downloadCount: updated.downloadCount },
    });
    return { manifest: row.manifest, bundle: row.bundle, classification: row.classification };
  }

  /* ------------------------------ auditor access ----------------------------- */

  async grantAuditorAccess(user: RequestUser, workspaceId: string, input: GrantAuditorAccessInput) {
    requireGrcPermission(user, "MANAGE_AUDITS");
    // Time-limited means bounded (§74/§75): expiry must be in the future
    // and within 90 days — enforced here as well as in the DTO schema so
    // no caller can mint a de-facto permanent grant.
    const expiresMs = new Date(input.expiresAt).getTime();
    const nowMs = Date.now();
    if (!Number.isFinite(expiresMs) || expiresMs <= nowMs || expiresMs > nowMs + 90 * 86400000) {
      throw new BadRequestException('expiresAt must be in the future and within 90 days');
    }
    // Explicit-share (§74/§75): the grantee must be a real member of this
    // workspace, and every shared evidence id must exist in it — mirroring
    // the assessmentIds validation below.
    const member = await this.prisma.workspaceMembership.findFirst({ where: { workspaceId, userId: input.userId } });
    if (!member) throw new BadRequestException('Grantee is not a member of this workspace');
    for (const assessmentId of input.assessmentIds) {
      const a = await this.prisma.complianceAssessment.findFirst({ where: { id: assessmentId, workspaceId } });
      if (!a) throw new BadRequestException(`Assessment ${assessmentId} does not exist in this workspace`);
    }
    for (const evidenceId of input.evidenceIds ?? []) {
      const ev = await this.prisma.complianceEvidence.findFirst({ where: { id: evidenceId, workspaceId } });
      if (!ev) throw new BadRequestException('Evidence ' + evidenceId + ' does not exist in this workspace');
    }
    const row = await this.prisma.auditorAccessGrant.create({
      data: {
        workspaceId, userId: input.userId, assessmentIds: input.assessmentIds,
        evidenceIds: input.evidenceIds ?? [], grantedBy: user.id, expiresAt: new Date(input.expiresAt),
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "AUDIT_CREATED", resourceType: "AuditorAccessGrant", resourceId: row.id,
      metadata: { userId: input.userId, expiresAt: input.expiresAt },
    });
    return row;
  }

  async revokeAuditorAccess(user: RequestUser, workspaceId: string, grantId: string) {
    requireGrcPermission(user, "MANAGE_AUDITS");
    const row = await this.prisma.auditorAccessGrant.findFirst({ where: { id: grantId, workspaceId } });
    if (!row) throw new NotFoundException("Grant not found in this workspace");
    return this.prisma.auditorAccessGrant.update({ where: { id: grantId }, data: { revokedAt: new Date() } });
  }

  async listGrants(user: RequestUser, workspaceId: string) {
    requireGrcPermission(user, "VIEW_AUDITS");
    const items = await this.prisma.auditorAccessGrant.findMany({
      where: { workspaceId }, orderBy: { createdAt: "desc" },
    });
    return { items, total: items.length };
  }
}

export { hashEvidence };
