import { BadRequestException, Inject, Injectable } from "@nestjs/common";
import { PLAN_SOURCES, REMEDIATION_OPTIONS } from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { CaseStateService } from "./case-state.service";
import { requireRemediationPermission } from "./permissions";

/**
 * Remediation plans (Prompt 31 §32–§37). A plan's fixed version must
 * trace to TRUSTED patch intelligence (§34): the finding's own P12/P30
 * fixed-version data or a component-vulnerability match carrying one.
 * A fixed version that appears from nowhere is rejected — for humans
 * and, by the same rule, for AI drafts (§35/§151). Mitigation and the
 * permanent fix are separate fields (§37).
 */
@Injectable()
export class RemediationPlansService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly state: CaseStateService,
  ) {}

  /** Fixed versions the platform can actually back with intelligence. */
  async trustedFixedVersions(workspaceId: string, findingId: string): Promise<string[]> {
    const finding = await this.state.getFinding(workspaceId, findingId);
    const versions = new Set<string>();
    if (finding.fixedVersion) versions.add(finding.fixedVersion);
    if (finding.cve) {
      // P30 Patch Intelligence: a fixedVersion exists ONLY where a
      // reliable source provides it (§34/§85 there) — the trusted set.
      const patches = await this.prisma.patchRecord.findMany({
        where: { cveId: finding.cve }, take: 200,
      });
      for (const p of patches as Array<{ fixedVersion?: string | null }>) {
        if (p.fixedVersion) versions.add(p.fixedVersion);
      }
    }
    return [...versions];
  }

  async createPlan(user: RequestUser, workspaceId: string, caseId: string, input: {
    summary: string; recommendedAction: string; source: string;
    patchReference?: string; fixedVersion?: string; targetVersion?: string;
    mitigation?: string; permanentFix?: string; ownerId?: string;
    plannedAt?: Date; targetDate?: Date;
  }) {
    requireRemediationPermission(user, "MANAGE_REMEDIATION_PLAN");
    if (!(REMEDIATION_OPTIONS as readonly string[]).includes(input.recommendedAction)) {
      throw new BadRequestException(`recommendedAction must be one of ${REMEDIATION_OPTIONS.join(", ")} (§36)`);
    }
    if (!(PLAN_SOURCES as readonly string[]).includes(input.source)) {
      throw new BadRequestException(`plan source must be one of ${PLAN_SOURCES.join(", ")} (§33)`);
    }
    if (!input.summary?.trim()) throw new BadRequestException("plan summary is required");
    const kase = await this.state.getCase(workspaceId, caseId);
    if (input.fixedVersion) {
      const trusted = await this.trustedFixedVersions(workspaceId, kase.findingId);
      if (!trusted.includes(input.fixedVersion)) {
        throw new BadRequestException(
          `fixed version ${input.fixedVersion} is not backed by trusted patch intelligence (§34) — trusted: ${trusted.join(", ") || "none recorded"}. Unbacked fix versions are never invented (§35).`,
        );
      }
    }
    // A new plan supersedes the previous DRAFT/APPROVED plan (§9 spirit:
    // the old row is kept, marked SUPERSEDED — never edited in place).
    await this.prisma.remediationPlan.updateMany({
      where: { caseId, status: { in: ["DRAFT", "APPROVED"] } }, data: { status: "SUPERSEDED" },
    });
    const plan = await this.prisma.remediationPlan.create({
      data: {
        caseId, workspaceId, summary: input.summary, recommendedAction: input.recommendedAction,
        source: input.source, patchReference: input.patchReference ?? null,
        fixedVersion: input.fixedVersion ?? null, targetVersion: input.targetVersion ?? null,
        mitigation: input.mitigation ?? null, permanentFix: input.permanentFix ?? null,
        ownerId: input.ownerId ?? null, plannedAt: input.plannedAt ?? null,
        targetDate: input.targetDate ?? null, status: "APPROVED", createdBy: user.id,
      },
    });
    let updated: import("./case-state.service").CaseRow = await this.prisma.remediationCase.update({
      where: { id: caseId }, data: { remediationPlanId: plan.id } as never,
    }) as import("./case-state.service").CaseRow;
    if (["TRIAGED", "ASSIGNED"].includes(kase.status)) {
      updated = await this.state.transition(user, workspaceId, kase, { to: "PLANNED", reason: "remediation plan created" });
      updated = await this.prisma.remediationCase.update({
        where: { id: caseId }, data: { remediationPlanId: plan.id } as never,
      }) as import("./case-state.service").CaseRow;
    }
    await this.state.emit(user, workspaceId, kase, "REMEDIATION_PLAN_CREATED", { planId: plan.id, action: input.recommendedAction });
    return { case: updated, plan };
  }
}
