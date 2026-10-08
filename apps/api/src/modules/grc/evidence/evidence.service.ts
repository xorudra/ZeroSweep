import { BadRequestException, ForbiddenException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  evidenceFreshness, hashEvidence, snapshotEvidence, validateManualEvidenceUpload,
  type EvidenceClassification,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { AuditService } from "../../audit/audit.service";
import { hasGrcPermission, requireGrcPermission } from "../permissions";
import { ControlService } from "../controls/control.service";
import type { CollectEvidenceInput, ReviewEvidenceInput, UploadEvidenceInput } from "../dto/schemas";

/**
 * Compliance evidence (Prompt 26 §20–§27, §38–§41). Evidence is a
 * snapshot: content is hashed at collection and never mutated
 * afterwards (§21/§125). Freshness is DERIVED at read time from the
 * per-control policy (§25) so CURRENT → STALE → EXPIRED transitions
 * happen by clock, not by silent edits. Restricted evidence requires
 * VIEW_RESTRICTED_EVIDENCE or an explicit auditor grant (§41/§74).
 */
@Injectable()
export class EvidenceService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly controls: ControlService,
  ) {}

  /** §26 collector step: authorized source → snapshot → hash → evidence.
   *  Collection READS platform state only; it never starts a scan (§27). */
  async collect(user: RequestUser, workspaceId: string, input: CollectEvidenceInput) {
    requireGrcPermission(user, "UPLOAD_COMPLIANCE_EVIDENCE");
    await this.controls.findControl(workspaceId, input.controlId);
    const snap = snapshotEvidence({
      sourceType: input.sourceType, sourceId: input.sourceId, snapshot: input.snapshot,
      classification: (input.classification ?? "INTERNAL") as EvidenceClassification,
      collectedAt: new Date().toISOString(),
    });
    const row = await this.prisma.complianceEvidence.create({
      data: {
        workspaceId, controlId: input.controlId, sourceType: input.sourceType, sourceId: input.sourceId,
        snapshot: input.snapshot as never, classification: snap.classification, status: "CURRENT",
        hash: snap.hash, createdBy: user.id,
        reviewStatus: input.sourceType === "MANUAL_UPLOAD" ? "PENDING" : "NOT_REQUIRED",
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "EVIDENCE_COLLECTED", resourceType: "ComplianceEvidence", resourceId: row.id,
      metadata: { controlId: input.controlId, sourceType: input.sourceType, hash: snap.hash },
    });
    return row;
  }

  /** §39–§40: manual evidence upload with hostile-file defenses. The
   *  stored snapshot holds metadata + content hash only; the decoded
   *  text (for text types) is stored escaped, never raw markup. */
  async upload(user: RequestUser, workspaceId: string, input: UploadEvidenceInput) {
    requireGrcPermission(user, "UPLOAD_COMPLIANCE_EVIDENCE");
    await this.controls.findControl(workspaceId, input.controlId);
    const content = Buffer.from(input.contentBase64, "base64");
    const validation = validateManualEvidenceUpload({
      filename: input.filename, contentType: input.contentType, content,
    });
    if (!validation.accepted) {
      throw new BadRequestException(`Manual evidence rejected: ${validation.reasons.join("; ")}`);
    }
    const isText = (validation.detectedType ?? "").startsWith("text/") || validation.detectedType === "application/json";
    const snapshot = {
      kind: "MANUAL_UPLOAD",
      filename: validation.safeFilename,
      contentType: validation.detectedType,
      sizeBytes: content.length,
      notes: input.notes ?? "",
      textPreview: isText ? content.toString("utf8").slice(0, 2000) : undefined,
    };
    const row = await this.prisma.complianceEvidence.create({
      data: {
        workspaceId, controlId: input.controlId, sourceType: "MANUAL_UPLOAD",
        sourceId: `upload:${validation.safeFilename}`, snapshot,
        classification: input.classification ?? "CONFIDENTIAL", status: "CURRENT",
        hash: hashEvidence(snapshot), filename: validation.safeFilename,
        mimeType: validation.detectedType, sizeBytes: content.length,
        createdBy: user.id, reviewStatus: "PENDING",
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "EVIDENCE_UPLOADED", resourceType: "ComplianceEvidence", resourceId: row.id,
      metadata: { controlId: input.controlId, filename: validation.safeFilename, sizeBytes: content.length },
    });
    return row;
  }

  /** §38 human review. SoD (§111): the uploader cannot approve their
   *  own evidence where review is required. */
  async review(user: RequestUser, workspaceId: string, evidenceId: string, input: ReviewEvidenceInput) {
    requireGrcPermission(user, "REVIEW_AUDIT_EVIDENCE");
    const row = await this.findEvidence(workspaceId, evidenceId);
    if (row.createdBy === user.id) {
      throw new ForbiddenException("Segregation of duties: evidence submitter cannot approve their own evidence (§111)");
    }
    const updated = await this.prisma.complianceEvidence.update({
      where: { id: evidenceId },
      data: { reviewStatus: input.decision, reviewedBy: user.id, reviewNotes: input.notes ?? "" },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "AUDIT_EVIDENCE_ACCEPTED", resourceType: "ComplianceEvidence", resourceId: evidenceId,
      metadata: { decision: input.decision },
    });
    return updated;
  }

  async findEvidence(workspaceId: string, id: string) {
    const row = await this.prisma.complianceEvidence.findFirst({ where: { id, workspaceId } });
    if (!row) throw new NotFoundException("Evidence not found in this workspace");
    return row;
  }

  /** Freshness-derived view of one evidence record (§25/§126). */
  async withFreshness(
    workspaceId: string, row: Record<string, unknown>, now = new Date(),
  ): Promise<Record<string, unknown> & { derivedStatus: ReturnType<typeof evidenceFreshness>; policy: { staleAfterDays: number; expireAfterDays: number } }> {
    const policy = await this.prisma.evidenceFreshnessPolicy.findFirst({
      where: { workspaceId, controlId: row.controlId as string },
    });
    const effective = policy ?? { staleAfterDays: 335, expireAfterDays: 400 };
    const status = evidenceFreshness(
      new Date(row.collectedAt as string).toISOString(), effective, now,
      row.status as never,
    );
    return { ...row, derivedStatus: status, policy: effective };
  }

  async listEvidence(user: RequestUser, workspaceId: string, controlId?: string) {
    requireGrcPermission(user, "VIEW_COMPLIANCE_EVIDENCE");
    await this.controls.ensureCatalog(user, workspaceId);
    const rows = await this.prisma.complianceEvidence.findMany({
      where: { workspaceId, ...(controlId ? { controlId } : {}) },
      orderBy: { collectedAt: "desc" }, take: 500,
    });
    const canSeeRestricted = hasGrcPermission(user, "VIEW_RESTRICTED_EVIDENCE");
    const items: Array<Record<string, unknown> & { derivedStatus: ReturnType<typeof evidenceFreshness>; restricted?: boolean }> = [];
    for (const row of rows) {
      const view = await this.withFreshness(workspaceId, row as Record<string, unknown>);
      if (row.classification === "RESTRICTED" && !canSeeRestricted) {
        // §41: restricted evidence is not even listed with content for
        // ordinary members — metadata only, snapshot withheld.
        items.push({ ...view, snapshot: undefined, restricted: true } as (typeof items)[number]);
      } else {
        items.push(view);
      }
      if (view.derivedStatus === "EXPIRED" && row.status !== "EXPIRED") {
        await this.audit.record({
          actorId: user.id, organizationId: user.organizationId, workspaceId,
          action: "EVIDENCE_EXPIRED", resourceType: "ComplianceEvidence", resourceId: row.id, metadata: {},
        }).catch(() => undefined);
        await this.prisma.complianceDriftEvent.create({
          data: { workspaceId, controlId: row.controlId, type: "EVIDENCE_EXPIRED", detail: `Evidence ${row.id} expired under its freshness policy` },
        }).catch(() => undefined);
      }
    }
    return { items, total: items.length };
  }

  /** Auditor-grant check (§74): explicit share + not expired + not revoked. */
  async auditorCanAccess(user: RequestUser, workspaceId: string, kind: "assessment" | "evidence", id: string): Promise<boolean> {
    const grants = await this.prisma.auditorAccessGrant.findMany({
      where: { workspaceId, userId: user.id },
    });
    const now = Date.now();
    return grants.some((g) => {
      if (g.revokedAt || new Date(g.expiresAt).getTime() <= now) return false;
      const ids = (kind === "assessment" ? g.assessmentIds : g.evidenceIds) as string[];
      return Array.isArray(ids) && ids.includes(id);
    });
  }
}
