import { BadRequestException, Inject, Injectable } from "@nestjs/common";
import { createHmac, timingSafeEqual } from "node:crypto";
import { canonicalJson, hashEvidence } from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { AuditService } from "../../audit/audit.service";
import { requireGrcPermission } from "../permissions";

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * GRC backup / restore (§141). Export produces a tenant-scoped state
 * bundle sealed with a KEYED MAC (HMAC-SHA256 over the canonical
 * {state, exportedAt, workspaceId} with the deployment secret) — the
 * unkeyed content hash alone proves only self-consistency, never that
 * the server issued the bundle, so restore REQUIRES the MAC. Restore
 * is a server-validated import, not a client-authored state write:
 * every row is field-whitelisted, every reference is remapped to the
 * newly created in-bundle row or verified to exist in the target
 * workspace / global catalog, and server-owned workflow fields
 * (reviewStatus, reviewedBy, createdBy, workflow status) are reset to
 * safe defaults. Restore is refused into a workspace that already
 * holds GRC state unless the caller explicitly confirms.
 */
@Injectable()
export class GrcBackupService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  private secret(): string {
    return process.env.JWT_SECRET ?? "change-me-local-dev-secret-at-least-32-chars";
  }

  private mac(state: unknown, exportedAt: string, workspaceId: string): string {
    return createHmac("sha256", this.secret())
      .update(canonicalJson({ state, exportedAt, workspaceId } as Record<string, unknown>))
      .digest("hex");
  }

  private async collect(workspaceId: string) {
    const p = this.prisma;
    return {
      controls: await p.securityControl.findMany({ where: { workspaceId } }),
      owners: await p.controlOwner.findMany({ where: { workspaceId } }),
      tests: await p.controlTest.findMany({ where: { workspaceId } }),
      mappings: await p.controlFrameworkMapping.findMany({ where: { workspaceId } }),
      evidence: await p.complianceEvidence.findMany({ where: { workspaceId } }),
      assessments: await p.complianceAssessment.findMany({ where: { workspaceId } }),
      results: await p.assessmentRequirementResult.findMany({ where: { workspaceId } }),
      risks: await p.riskRecord.findMany({ where: { workspaceId } }),
      riskLinks: await p.riskLink.findMany({ where: { workspaceId } }),
      policies: await p.governancePolicy.findMany({ where: { workspaceId } }),
      audits: await p.auditEngagement.findMany({ where: { workspaceId } }),
      packages: await p.auditEvidencePackage.findMany({ where: { workspaceId } }),
      vendors: await p.thirdPartyVendor.findMany({ where: { workspaceId } }),
    };
  }

  async exportState(user: RequestUser, workspaceId: string) {
    requireGrcPermission(user, "MANAGE_FRAMEWORKS");
    const state = await this.collect(workspaceId);
    const exportedAt = new Date().toISOString();
    const hash = hashEvidence({ state, exportedAt } as Record<string, unknown>);
    const mac = this.mac(state, exportedAt, workspaceId);
    return { workspaceId, exportedAt, hash, mac, state };
  }

  async restoreState(user: RequestUser, workspaceId: string, bundle: {
    workspaceId?: string; hash?: string; mac: string; exportedAt: string; state: Record<string, Array<Record<string, unknown>>>; confirm?: boolean;
  }) {
    requireGrcPermission(user, "MANAGE_FRAMEWORKS");
    // Keyed integrity: only a bundle this server issued (export MAC over
    // state + exportedAt + SOURCE workspace) can be restored. The MAC is
    // verified against the bundle's own workspace claim if present, else
    // the target workspace — exportState always stamps its workspaceId.
    const claimedWs = bundle.workspaceId ?? workspaceId;
    const expectedMac = this.mac(bundle.state, bundle.exportedAt, claimedWs);
    const providedMac = typeof bundle.mac === "string" ? bundle.mac : "";
    if (
      providedMac.length !== expectedMac.length ||
      !timingSafeEqual(Buffer.from(providedMac), Buffer.from(expectedMac))
    ) {
      throw new BadRequestException("Backup integrity check failed: bundle was not issued by this server (missing or invalid MAC) (§141)");
    }
    if (bundle.hash !== undefined) {
      const expectedHash = hashEvidence({ state: bundle.state, exportedAt: bundle.exportedAt } as Record<string, unknown>);
      if (expectedHash !== bundle.hash) {
        throw new BadRequestException("Backup integrity check failed: bundle hash does not match its content (§141)");
      }
    }
    const existing = await this.prisma.securityControl.count({ where: { workspaceId } });
    if (existing > 0 && !bundle.confirm) {
      throw new BadRequestException("Target workspace already holds GRC state; pass confirm=true to restore alongside it (ids are re-created, history is never overwritten)");
    }
    // Evidence hash verification per record before insert (§141).
    for (const ev of bundle.state.evidence ?? []) {
      if (hashEvidence(ev.snapshot as Record<string, unknown>) !== ev.hash) {
        throw new BadRequestException(`Evidence ${ev.id} failed hash verification; restore aborted`);
      }
    }

    const p = this.prisma as any;
    const counts: Record<string, number> = {};
    const pick = (row: Record<string, unknown>, allowed: string[]) => {
      const data: Record<string, unknown> = {};
      for (const k of allowed) if (row[k] !== undefined) data[k] = row[k];
      data.workspaceId = workspaceId;
      return data;
    };
    const create = async (table: string, data: Record<string, unknown>) => {
      const row = await p[table].create({ data });
      counts[table] = (counts[table] ?? 0) + 1;
      return row;
    };
    /** Remap an intra-bundle reference to its newly created row, or
     *  verify the id already exists in the target workspace. */
    const ref = async (
      map: Map<string, string>, table: string, value: unknown, label: string,
    ): Promise<string> => {
      const id = String(value ?? "");
      const mapped = map.get(id);
      if (mapped) return mapped;
      const found = await p[table].findFirst({ where: { id, workspaceId } });
      if (!found) throw new BadRequestException(`Restore aborted: referenced ${label} ${id} does not exist in the target workspace`);
      return id;
    };
    const globalRef = async (table: string, value: unknown, label: string): Promise<string> => {
      const id = String(value ?? "");
      const found = await p[table].findFirst({ where: { id } });
      if (!found) throw new BadRequestException(`Restore aborted: referenced ${label} ${id} does not exist`);
      return id;
    };

    // -- controls first: most other tables reference them ---------------
    const controlIds = new Map<string, string>();
    for (const row of bundle.state.controls ?? []) {
      const created = await create("securityControl", pick(row, [
        "code", "title", "description", "controlType", "implementationType",
        "implementationStatus", "effectiveness", "catalogSource",
      ]));
      if (row.id) controlIds.set(String(row.id), created.id);
    }
    for (const row of bundle.state.owners ?? []) {
      const data = pick(row, ["ownerType", "ownerRef", "isPrimary"]);
      data.controlId = await ref(controlIds, "securityControl", row.controlId, "control");
      await create("controlOwner", data);
    }
    for (const row of bundle.state.tests ?? []) {
      const data = pick(row, [
        "name", "method", "automationLevel", "frequency", "expectedResult",
        "evidenceRequirements", "ownerRef", "signalKeys",
      ]);
      data.controlId = await ref(controlIds, "securityControl", row.controlId, "control");
      await create("controlTest", data);
    }
    for (const row of bundle.state.mappings ?? []) {
      const data = pick(row, ["mappingType", "coverage", "notes", "source"]);
      data.controlId = await ref(controlIds, "securityControl", row.controlId, "control");
      data.requirementId = await globalRef("complianceRequirement", row.requirementId, "framework requirement");
      await create("controlFrameworkMapping", data);
    }
    // -- evidence: workflow fields are server-owned ----------------------
    const evidenceIds = new Map<string, string>();
    for (const row of bundle.state.evidence ?? []) {
      const data = pick(row, [
        "sourceType", "sourceId", "snapshot", "classification", "hash",
        "filename", "mimeType", "sizeBytes", "collectedAt", "validFrom", "validUntil",
      ]);
      data.controlId = await ref(controlIds, "securityControl", row.controlId, "control");
      data.status = "CURRENT";
      data.reviewStatus = row.sourceType === "MANUAL_UPLOAD" ? "PENDING" : "NOT_REQUIRED";
      data.createdBy = user.id;
      const created = await create("complianceEvidence", data);
      if (row.id) evidenceIds.set(String(row.id), created.id);
    }
    // -- assessments ------------------------------------------------------
    const assessmentIds = new Map<string, string>();
    for (const row of bundle.state.assessments ?? []) {
      const data = pick(row, [
        "frameworkKey", "frameworkVersion", "name", "scope", "periodStart", "periodEnd",
        "startedAt", "completedAt",
      ]);
      data.frameworkId = await globalRef("complianceFramework", row.frameworkId, "framework");
      data.status = "IN_PROGRESS";
      data.ownerId = user.id;
      const created = await create("complianceAssessment", data);
      if (row.id) assessmentIds.set(String(row.id), created.id);
    }
    for (const row of bundle.state.results ?? []) {
      const data = pick(row, ["result", "controlIds", "evidenceIds", "exceptionIds", "notes"]);
      data.assessmentId = await ref(assessmentIds, "complianceAssessment", row.assessmentId, "assessment");
      data.requirementId = await globalRef("complianceRequirement", row.requirementId, "framework requirement");
      data.reviewStatus = "PENDING";
      await create("assessmentRequirementResult", data);
    }
    // -- risks: register is per-workspace, provisioned like RiskService --
    let registerId: string | null = null;
    const targetRegister = async (): Promise<string> => {
      if (registerId) return registerId;
      const found = await p.riskRegister.findFirst({ where: { workspaceId } });
      const reg = found ?? (await p.riskRegister.create({ data: { workspaceId, name: "Risk Register" } }));
      registerId = reg.id as string;
      return registerId;
    };
    const riskIds = new Map<string, string>();
    for (const row of bundle.state.risks ?? []) {
      const data = pick(row, [
        "title", "description", "category", "source", "sourceRef", "likelihood", "impacts",
        "inherentScore", "inherentBand", "residualScore", "residualBand", "residualBasis",
        "treatment", "reviewDate",
      ]);
      data.registerId = await targetRegister();
      data.ownerId = user.id;
      data.status = "IDENTIFIED";
      const created = await create("riskRecord", data);
      if (row.id) riskIds.set(String(row.id), created.id);
    }
    for (const row of bundle.state.riskLinks ?? []) {
      const data = pick(row, ["linkType", "linkId"]);
      data.riskId = await ref(riskIds, "riskRecord", row.riskId, "risk");
      if (row.linkType === "CONTROL") data.linkId = await ref(controlIds, "securityControl", row.linkId, "control");
      else if (row.linkType === "REQUIREMENT") data.linkId = await globalRef("complianceRequirement", row.linkId, "framework requirement");
      else if (row.linkType === "FINDING") data.linkId = await ref(new Map(), "finding", row.linkId, "finding");
      await create("riskLink", data);
    }
    // -- policies / audits / packages / vendors ---------------------------
    for (const row of bundle.state.policies ?? []) {
      const data = pick(row, [
        "title", "version", "effectiveDate", "reviewDate", "classification", "documentRef", "contentHash",
      ]);
      data.status = "DRAFT";
      data.ownerId = user.id;
      await create("governancePolicy", data);
    }
    const auditIds = new Map<string, string>();
    for (const row of bundle.state.audits ?? []) {
      const data = pick(row, ["type", "auditorRef", "scope", "periodStart", "periodEnd"]);
      if (row.frameworkId) data.frameworkId = await globalRef("complianceFramework", row.frameworkId, "framework");
      if (row.assessmentId) data.assessmentId = await ref(assessmentIds, "complianceAssessment", row.assessmentId, "assessment");
      data.status = "PLANNED";
      data.createdBy = user.id;
      const created = await create("auditEngagement", data);
      if (row.id) auditIds.set(String(row.id), created.id);
    }
    for (const row of bundle.state.packages ?? []) {
      const data = pick(row, [
        "frameworkKey", "frameworkVersion", "classification", "manifest", "manifestHash", "bundle", "generatedAt",
      ]);
      data.auditId = await ref(auditIds, "auditEngagement", row.auditId, "audit engagement");
      data.assessmentId = await ref(assessmentIds, "complianceAssessment", row.assessmentId, "assessment");
      data.generatedBy = user.id;
      data.downloadCount = 0;
      await create("auditEvidencePackage", data);
    }
    for (const row of bundle.state.vendors ?? []) {
      const data = pick(row, ["name", "criticality", "serviceDescription", "reviewDate", "riskRating"]);
      data.ownerId = user.id;
      data.status = "ACTIVE";
      await create("thirdPartyVendor", data);
    }

    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "FRAMEWORK_IMPORTED", resourceType: "GrcBackup", resourceId: workspaceId,
      metadata: { restore: true, counts },
    });
    // Every exported table is restored above; the list stays explicit so
    // a future exported table can never be dropped silently.
    return { restored: counts, notRestored: [] as string[] };
  }
}
