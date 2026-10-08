import { BadRequestException, ForbiddenException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import { GRC_DISCLAIMER, evidenceFreshness, requirementResult, type MappedControlOutcome } from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { AuditService } from "../../audit/audit.service";
import { hasGrcPermission, requireGrcPermission } from "../permissions";
import { ControlService } from "../controls/control.service";
import { EvidenceService } from "../evidence/evidence.service";
import type { CreateAssessmentInput, ReviewRequirementInput } from "../dto/schemas";

/**
 * Compliance assessments (Prompt 26 §33–§38). An assessment is pinned
 * to the exact framework version it was created against (§122) and its
 * requirement results are COMPUTED FROM SNAPSHOTS at completion:
 * control evaluations + immutable evidence as they stood — later
 * source changes never rewrite a completed assessment (§21/§125).
 * Results are assessment states, not certification claims (§37).
 */
@Injectable()
export class AssessmentService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly controls: ControlService,
    private readonly evidence: EvidenceService,
  ) {}

  async createAssessment(user: RequestUser, workspaceId: string, input: CreateAssessmentInput) {
    requireGrcPermission(user, "MANAGE_ASSESSMENTS");
    await this.controls.ensureCatalog(user, workspaceId);
    const framework = await this.prisma.complianceFramework.findFirst({ where: { id: input.frameworkId } });
    if (!framework) throw new NotFoundException("Framework not found");
    if (framework.status === "RETIRED") throw new BadRequestException("Cannot start an assessment against a RETIRED framework version (§5)");
    const row = await this.prisma.complianceAssessment.create({
      data: {
        workspaceId, frameworkId: framework.id, frameworkKey: framework.key, frameworkVersion: framework.version,
        name: input.name, scope: (input.scope ?? {}) as never, periodStart: input.periodStart ? new Date(input.periodStart) : null,
        periodEnd: input.periodEnd ? new Date(input.periodEnd) : null, status: "IN_PROGRESS",
        ownerId: user.id, reviewerId: input.reviewerId ?? null, startedAt: new Date(),
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "ASSESSMENT_CREATED", resourceType: "ComplianceAssessment", resourceId: row.id,
      metadata: { frameworkKey: framework.key, frameworkVersion: framework.version },
    });
    return row;
  }

  async listAssessments(user: RequestUser, workspaceId: string) {
    requireGrcPermission(user, "VIEW_GRC");
    const items = await this.prisma.complianceAssessment.findMany({
      where: { workspaceId }, orderBy: { createdAt: "desc" },
    });
    return { items, total: items.length, disclaimer: GRC_DISCLAIMER };
  }

  async getAssessment(user: RequestUser, workspaceId: string, id: string) {
    const assessment = await this.prisma.complianceAssessment.findFirst({ where: { id, workspaceId } });
    if (!assessment) throw new NotFoundException("Assessment not found in this workspace");
    if (!hasGrcPermission(user, "VIEW_GRC")) {
      const granted = await this.evidence.auditorCanAccess(user, workspaceId, "assessment", id);
      if (!granted) throw new ForbiddenException("No access to this assessment (§74)");
    }
    const results = await this.prisma.assessmentRequirementResult.findMany({
      where: { workspaceId, assessmentId: id }, orderBy: { createdAt: "asc" },
    });
    return { ...assessment, results, disclaimer: GRC_DISCLAIMER };
  }

  /** Compute requirement results from current evaluations + evidence
   *  and store them as the assessment's snapshot (§36). Idempotent:
   *  recomputing replaces PENDING results only before completion. */
  async computeResults(user: RequestUser, workspaceId: string, assessmentId: string) {
    requireGrcPermission(user, "MANAGE_ASSESSMENTS");
    const assessment = await this.mustFind(workspaceId, assessmentId);
    if (assessment.status === "COMPLETED" || assessment.status === "ARCHIVED") {
      throw new BadRequestException("Assessment is completed; its results are an immutable snapshot (§21)");
    }
    const requirements = await this.prisma.complianceRequirement.findMany({
      where: { frameworkId: assessment.frameworkId }, orderBy: { requirementId: "asc" },
    });
    const mappings = await this.prisma.controlFrameworkMapping.findMany({ where: { workspaceId } });
    const now = new Date();
    const computed = [];
    for (const req of requirements) {
      const reqMappings = mappings.filter((m) => m.requirementId === req.id);
      const outcomes: MappedControlOutcome[] = [];
      const controlIds: string[] = [];
      const evidenceIds: string[] = [];
      for (const m of reqMappings) {
        controlIds.push(m.controlId);
        const evaluation = await this.prisma.controlEvaluation.findFirst({
          where: { workspaceId, controlId: m.controlId }, orderBy: { evaluatedAt: "desc" },
        });
        const controlEvidence = await this.prisma.complianceEvidence.findMany({
          where: { workspaceId, controlId: m.controlId }, orderBy: { collectedAt: "desc" }, take: 20,
        });
        const policy = await this.prisma.evidenceFreshnessPolicy.findFirst({
          where: { workspaceId, controlId: m.controlId },
        });
        const effective = policy ?? { staleAfterDays: 335, expireAfterDays: 400 };
        const usable = controlEvidence.filter((e) => {
          const fresh = evidenceFreshness(new Date(e.collectedAt).toISOString(), effective, now, e.status as never);
          const reviewed = e.reviewStatus === "NOT_REQUIRED" || e.reviewStatus === "APPROVED";
          return fresh === "CURRENT" && reviewed && e.status !== "INVALID" && e.status !== "SUPERSEDED";
        });
        evidenceIds.push(...usable.map((e) => e.id));
        outcomes.push({
          mappingType: m.mappingType as MappedControlOutcome["mappingType"],
          coverage: m.coverage,
          controlResult: (evaluation?.result as MappedControlOutcome["controlResult"]) ?? "INCONCLUSIVE",
          hasCurrentEvidence: usable.length > 0,
          manuallySatisfied: controlEvidence.some((e) => e.sourceType === "MANUAL_UPLOAD" && e.reviewStatus === "APPROVED"),
        });
      }
      const result = requirementResult(outcomes);
      const existing = await this.prisma.assessmentRequirementResult.findFirst({
        where: { assessmentId, requirementId: req.id },
      });
      const data = {
        workspaceId, assessmentId, requirementId: req.id, result,
        controlIds, evidenceIds, exceptionIds: [],
        notes: outcomes.length === 0 ? "No mapped controls — NOT_ASSESSED (§37)" : "",
      };
      const row = existing
        ? await this.prisma.assessmentRequirementResult.update({ where: { id: existing.id }, data })
        : await this.prisma.assessmentRequirementResult.create({ data });
      computed.push(row);
    }
    return { assessmentId, results: computed };
  }

  async completeAssessment(user: RequestUser, workspaceId: string, assessmentId: string) {
    requireGrcPermission(user, "MANAGE_ASSESSMENTS");
    const assessment = await this.mustFind(workspaceId, assessmentId);
    if (assessment.status === "COMPLETED") throw new BadRequestException("Assessment already completed");
    await this.computeResults(user, workspaceId, assessmentId);
    const updated = await this.prisma.complianceAssessment.update({
      where: { id: assessmentId }, data: { status: "READY_FOR_REVIEW" },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "GRC_ASSESSMENT_COMPLETED", resourceType: "ComplianceAssessment", resourceId: assessmentId,
      metadata: { stage: "READY_FOR_REVIEW" },
    });
    return updated;
  }

  /** §38 review of one requirement result (approve / reject / changes). */
  async reviewRequirement(user: RequestUser, workspaceId: string, assessmentId: string, resultId: string, input: ReviewRequirementInput) {
    requireGrcPermission(user, "REVIEW_ASSESSMENTS");
    const assessment = await this.mustFind(workspaceId, assessmentId);
    if (assessment.ownerId === user.id) {
      throw new ForbiddenException("Segregation of duties: the assessment owner cannot review their own assessment (§111)");
    }
    const row = await this.prisma.assessmentRequirementResult.findFirst({
      where: { id: resultId, workspaceId, assessmentId },
    });
    if (!row) throw new NotFoundException("Requirement result not found");
    const updated = await this.prisma.assessmentRequirementResult.update({
      where: { id: resultId },
      data: { reviewStatus: input.decision, reviewedBy: user.id, notes: input.notes ?? row.notes },
    });
    // All results reviewed + none rejected → assessment COMPLETED.
    const all = await this.prisma.assessmentRequirementResult.findMany({ where: { workspaceId, assessmentId } });
    if (all.length > 0 && all.every((r) => r.reviewStatus === "APPROVED")) {
      await this.prisma.complianceAssessment.update({
        where: { id: assessmentId }, data: { status: "COMPLETED", completedAt: new Date() },
      });
      await this.audit.record({
        actorId: user.id, organizationId: user.organizationId, workspaceId,
        action: "GRC_ASSESSMENT_COMPLETED", resourceType: "ComplianceAssessment", resourceId: assessmentId,
        metadata: { stage: "COMPLETED" },
      });
    }
    return updated;
  }

  private async mustFind(workspaceId: string, id: string) {
    const row = await this.prisma.complianceAssessment.findFirst({ where: { id, workspaceId } });
    if (!row) throw new NotFoundException("Assessment not found in this workspace");
    return row;
  }
}
