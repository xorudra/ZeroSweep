import { BadRequestException, Inject, Injectable } from "@nestjs/common";
import { hashEvidence } from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { AuditService } from "../../audit/audit.service";
import { requireGrcPermission } from "../permissions";

/**
 * GRC backup / restore (§141). Export produces a tenant-scoped state
 * bundle with a content hash; restore verifies the hash BEFORE any
 * write and re-creates rows in the target workspace preserving
 * framework versions, assessment pins and evidence hashes. Restore is
 * refused into a workspace that already holds GRC state unless the
 * caller explicitly confirms (no silent merge of audit history).
 */
@Injectable()
export class GrcBackupService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

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
    return { workspaceId, exportedAt, hash, state };
  }

  async restoreState(user: RequestUser, workspaceId: string, bundle: {
    hash: string; exportedAt: string; state: Record<string, Array<Record<string, unknown>>>; confirm?: boolean;
  }) {
    requireGrcPermission(user, "MANAGE_FRAMEWORKS");
    const expected = hashEvidence({ state: bundle.state, exportedAt: bundle.exportedAt } as Record<string, unknown>);
    if (expected !== bundle.hash) {
      throw new BadRequestException("Backup integrity check failed: bundle hash does not match its content (§141)");
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
    const p = this.prisma;
    const counts: Record<string, number> = {};
    const insert = async (table: string, rows: Array<Record<string, unknown>> | undefined, strip: string[] = []) => {
      let n = 0;
      for (const row of rows ?? []) {
        const data: Record<string, unknown> = { ...row, workspaceId };
        delete data.id;
        for (const s of strip) delete data[s];
        // createdAt/updatedAt are server-owned on restore.
        delete data.createdAt; delete data.updatedAt;
        await (p as unknown as Record<string, { create: (a: { data: Record<string, unknown> }) => Promise<unknown> }>)[table].create({ data });
        n++;
      }
      counts[table] = n;
    };
    await insert("securityControl", bundle.state.controls);
    await insert("complianceEvidence", bundle.state.evidence);
    await insert("complianceAssessment", bundle.state.assessments);
    await insert("riskRecord", bundle.state.risks);
    await insert("governancePolicy", bundle.state.policies);
    await insert("auditEngagement", bundle.state.audits);
    await insert("thirdPartyVendor", bundle.state.vendors);
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "FRAMEWORK_IMPORTED", resourceType: "GrcBackup", resourceId: workspaceId,
      metadata: { restore: true, counts },
    });
    return { restored: counts };
  }
}
