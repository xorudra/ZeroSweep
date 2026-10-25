import { BadRequestException, ForbiddenException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  DEFAULT_RISK_MATRIX, acceptanceState, bandForScore, computeRegisterRisk, evaluateAcceptanceSod,
  validateMatrixConfig, type RiskMatrixConfig,
} from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { AuditService } from "../../audit/audit.service";
import { requireGrcPermission } from "../permissions";
import type {
  CreateReviewInput, CreateRiskInput, CreateTreatmentInput, DecideAcceptanceInput,
  RequestAcceptanceInput, UpdateMatrixInput, UpdateRiskInput,
} from "../dto/schemas";

/**
 * Risk register (Prompt 26 §42–§59). RiskEngine V3 remains
 * authoritative for TECHNICAL vulnerability risk (§54) — this
 * register never overwrites a finding's risk score; it layers
 * business impact, control effectiveness and manual context.
 * Inherent risk is computed at assessment time; residual risk is
 * stored ONLY when linked-control effectiveness is known (§49).
 * Acceptance follows SoD (§57) and expiry returns risks to review
 * (§59) — never silently accepted forever.
 */
@Injectable()
export class RiskService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  async ensureRegister(workspaceId: string) {
    const existing = await this.prisma.riskRegister.findFirst({ where: { workspaceId } });
    if (existing) return existing;
    return this.prisma.riskRegister.create({ data: { workspaceId, name: "Risk Register" } });
  }

  async getMatrix(workspaceId: string): Promise<RiskMatrixConfig> {
    const row = await this.prisma.riskMatrix.findFirst({ where: { workspaceId } });
    if (!row) return DEFAULT_RISK_MATRIX;
    return { ...DEFAULT_RISK_MATRIX, ...(row.config as object) } as RiskMatrixConfig;
  }

  async updateMatrix(user: RequestUser, workspaceId: string, input: UpdateMatrixInput) {
    requireGrcPermission(user, "MANAGE_RISKS");
    const errors = validateMatrixConfig(input as RiskMatrixConfig);
    if (errors.length > 0) throw new BadRequestException(errors.join("; "));
    const existing = await this.prisma.riskMatrix.findFirst({ where: { workspaceId } });
    const row = existing
      ? await this.prisma.riskMatrix.update({ where: { id: existing.id }, data: { config: input as never } })
      : await this.prisma.riskMatrix.create({ data: { workspaceId, config: input as never } });
    return row;
  }

  /** Residual derivation: worst (least effective) linked control wins —
   *  a risk is only as treated as its weakest linked control. */
  private async residualFor(workspaceId: string, riskId: string, likelihood: number, impacts: Record<string, number>, matrix: RiskMatrixConfig) {
    const links = await this.prisma.riskLink.findMany({ where: { workspaceId, riskId, linkType: "CONTROL" } });
    let effectiveness: string | null = null;
    const order = ["INEFFECTIVE", "PARTIALLY_EFFECTIVE", "EFFECTIVE"];
    for (const link of links) {
      const control = await this.prisma.securityControl.findFirst({ where: { id: link.linkId, workspaceId } });
      if (!control) continue;
      if (control.effectiveness === "NOT_TESTED" || control.effectiveness === "INCONCLUSIVE") continue;
      if (!effectiveness || order.indexOf(control.effectiveness) < order.indexOf(effectiveness)) {
        effectiveness = control.effectiveness;
      }
    }
    return computeRegisterRisk({ likelihood, impacts }, effectiveness as never, matrix);
  }

  async createRisk(user: RequestUser, workspaceId: string, input: CreateRiskInput) {
    requireGrcPermission(user, "MANAGE_RISKS");
    const register = await this.ensureRegister(workspaceId);
    const matrix = await this.getMatrix(workspaceId);
    const computed = computeRegisterRisk({ likelihood: input.likelihood, impacts: input.impacts }, null, matrix);
    const row = await this.prisma.riskRecord.create({
      data: {
        workspaceId, registerId: register.id, title: input.title, description: input.description ?? "",
        category: input.category ?? "SECURITY", source: input.source, sourceRef: input.sourceRef ?? null,
        likelihood: input.likelihood, impacts: input.impacts, inherentScore: computed.inherentScore,
        inherentBand: computed.inherentBand, residualScore: null, residualBand: null,
        residualBasis: computed.residualBasis, ownerId: input.ownerId ?? user.id, status: "ASSESSED",
        reviewDate: input.reviewDate ? new Date(input.reviewDate) : null,
      },
    });
    for (const link of input.links ?? []) {
      await this.prisma.riskLink.create({
        data: { workspaceId, riskId: row.id, linkType: link.linkType, linkId: link.linkId },
      });
    }
    // §53/§54: a TECHNICAL_FINDING risk links to the canonical finding
    // and READS its RiskEngine V3 band for context — never writes it.
    if (input.source === "TECHNICAL_FINDING" && input.sourceRef) {
      const already = (input.links ?? []).some((l) => l.linkType === "FINDING" && l.linkId === input.sourceRef);
      if (!already) {
        await this.prisma.riskLink.create({
          data: { workspaceId, riskId: row.id, linkType: "FINDING", linkId: input.sourceRef },
        });
      }
    }
    const withResidual = await this.recomputeResidual(workspaceId, row.id);
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "RISK_CREATED", resourceType: "RiskRecord", resourceId: row.id,
      metadata: { source: input.source, inherentBand: computed.inherentBand },
    });
    return withResidual;
  }

  async recomputeResidual(workspaceId: string, riskId: string) {
    const risk = await this.mustFindRisk(workspaceId, riskId);
    const matrix = await this.getMatrix(workspaceId);
    const computed = await this.residualFor(workspaceId, riskId, risk.likelihood, risk.impacts as Record<string, number>, matrix);
    return this.prisma.riskRecord.update({
      where: { id: riskId },
      data: {
        inherentScore: computed.inherentScore, inherentBand: computed.inherentBand,
        residualScore: computed.residualScore, residualBand: computed.residualBand, residualBasis: computed.residualBasis,
      },
    });
  }

  async listRisks(user: RequestUser, workspaceId: string) {
    requireGrcPermission(user, "VIEW_RISK_REGISTER");
    await this.expireAcceptances(user, workspaceId);
    const items = await this.prisma.riskRecord.findMany({ where: { workspaceId }, orderBy: { createdAt: "desc" } });
    return { items, total: items.length };
  }

  async getRisk(user: RequestUser, workspaceId: string, id: string) {
    requireGrcPermission(user, "VIEW_RISK_REGISTER");
    const risk = await this.mustFindRisk(workspaceId, id);
    const links = await this.prisma.riskLink.findMany({ where: { workspaceId, riskId: id } });
    const plans = await this.prisma.riskTreatmentPlan.findMany({ where: { workspaceId, riskId: id } });
    const acceptances = await this.prisma.riskAcceptance.findMany({ where: { workspaceId, riskId: id }, orderBy: { createdAt: "desc" } });
    const reviews = await this.prisma.riskReview.findMany({ where: { workspaceId, riskId: id }, orderBy: { createdAt: "desc" } });
    return { ...risk, links, plans, acceptances, reviews };
  }

  async updateRisk(user: RequestUser, workspaceId: string, id: string, input: UpdateRiskInput) {
    requireGrcPermission(user, "MANAGE_RISKS");
    const risk = await this.mustFindRisk(workspaceId, id);
    const data: Record<string, unknown> = {};
    for (const k of ["title", "description", "category", "ownerId", "status"] as const) {
      if (input[k] !== undefined) data[k] = input[k];
    }
    if (input.likelihood !== undefined) data.likelihood = input.likelihood;
    if (input.impacts !== undefined) data.impacts = input.impacts;
    if (input.reviewDate !== undefined) data.reviewDate = input.reviewDate ? new Date(input.reviewDate) : null;
    await this.prisma.riskRecord.update({ where: { id: risk.id }, data });
    const updated = await this.recomputeResidual(workspaceId, id);
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "RISK_UPDATED", resourceType: "RiskRecord", resourceId: id,
      metadata: { fields: Object.keys(data) },
    });
    return updated;
  }

  /* ----------------------------- treatments ----------------------------- */

  async createTreatment(user: RequestUser, workspaceId: string, riskId: string, input: CreateTreatmentInput) {
    requireGrcPermission(user, "MANAGE_RISKS");
    const risk = await this.mustFindRisk(workspaceId, riskId);
    const plan = await this.prisma.riskTreatmentPlan.create({
      data: { workspaceId, riskId, strategy: input.strategy, description: input.description ?? "", status: "PLANNED", createdBy: user.id },
    });
    const actions = [];
    for (const a of input.actions ?? []) {
      actions.push(await this.prisma.riskTreatmentAction.create({
        data: {
          workspaceId, planId: plan.id, action: a.action, ownerId: a.ownerId ?? user.id,
          dueDate: a.dueDate ? new Date(a.dueDate) : null, status: "OPEN",
          relatedFindingId: a.relatedFindingId ?? null, relatedControlId: a.relatedControlId ?? null,
          ticketRef: a.ticketRef ?? null,
        },
      }));
    }
    await this.prisma.riskRecord.update({
      where: { id: risk.id },
      data: { treatment: input.strategy, status: risk.status === "ASSESSED" || risk.status === "IDENTIFIED" ? "TREATMENT_PLANNED" : risk.status },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "RISK_UPDATED", resourceType: "RiskTreatmentPlan", resourceId: plan.id,
      metadata: { riskId, strategy: input.strategy },
    });
    return { ...plan, actions };
  }

  /* ----------------------------- acceptances ---------------------------- */

  async requestAcceptance(user: RequestUser, workspaceId: string, riskId: string, input: RequestAcceptanceInput) {
    requireGrcPermission(user, "MANAGE_RISKS");
    await this.mustFindRisk(workspaceId, riskId);
    const row = await this.prisma.riskAcceptance.create({
      data: {
        workspaceId, riskId, requestedBy: user.id, reason: input.reason, scope: (input.scope ?? {}) as never,
        compensatingControls: input.compensatingControls ?? [], status: "PENDING",
        expiresAt: new Date(input.expiresAt),
      },
    });
    return row;
  }

  /** §56/§57: approval with SoD — high/critical risks may not be
   *  self-approved. Band used is the risk's inherent band. */
  async decideAcceptance(user: RequestUser, workspaceId: string, riskId: string, acceptanceId: string, input: DecideAcceptanceInput) {
    requireGrcPermission(user, "APPROVE_RISK_ACCEPTANCE");
    const risk = await this.mustFindRisk(workspaceId, riskId);
    const acceptance = await this.prisma.riskAcceptance.findFirst({ where: { id: acceptanceId, workspaceId, riskId } });
    if (!acceptance) throw new NotFoundException("Acceptance request not found");
    if (acceptance.status !== "PENDING") throw new BadRequestException(`Acceptance already ${acceptance.status}`);
    if (input.decision === "ACCEPTED") {
      const sod = evaluateAcceptanceSod({
        requesterId: acceptance.requestedBy, approverId: user.id,
        inherentBand: risk.inherentBand as never, sodRequiredForBands: ["HIGH", "CRITICAL"],
      });
      if (!sod.allowed) throw new ForbiddenException(sod.reason);
    }
    const updated = await this.prisma.riskAcceptance.update({
      where: { id: acceptanceId }, data: { status: input.decision, approvedBy: user.id },
    });
    if (input.decision === "ACCEPTED") {
      await this.prisma.riskRecord.update({ where: { id: riskId }, data: { status: "ACCEPTED", treatment: "ACCEPT" } });
      await this.audit.record({
        actorId: user.id, organizationId: user.organizationId, workspaceId,
        action: "RISK_ACCEPTED", resourceType: "RiskAcceptance", resourceId: acceptanceId,
        metadata: { riskId, expiresAt: acceptance.expiresAt },
      });
    }
    return updated;
  }

  /** §59/§131: sweep — expired acceptances return their risks to review. */
  async expireAcceptances(user: RequestUser, workspaceId: string) {
    const now = new Date();
    const accepted = await this.prisma.riskAcceptance.findMany({ where: { workspaceId, status: "ACCEPTED" } });
    let expired = 0;
    for (const a of accepted) {
      if (acceptanceState({ status: a.status, expiresAt: new Date(a.expiresAt).toISOString() }, now) === "REVIEW_REQUIRED") {
        await this.prisma.riskAcceptance.update({ where: { id: a.id }, data: { status: "EXPIRED" } });
        const risk = await this.prisma.riskRecord.findFirst({ where: { id: a.riskId, workspaceId } });
        if (risk && risk.status === "ACCEPTED") {
          await this.prisma.riskRecord.update({ where: { id: a.riskId }, data: { status: "ASSESSED" } });
        }
        await this.audit.record({
          actorId: user.id, organizationId: user.organizationId, workspaceId,
          action: "RISK_ACCEPTANCE_EXPIRED", resourceType: "RiskAcceptance", resourceId: a.id,
          metadata: { riskId: a.riskId },
        });
        expired++;
      }
    }
    return { expired };
  }

  /* ------------------------------- reviews ------------------------------ */

  async createReview(user: RequestUser, workspaceId: string, riskId: string, input: CreateReviewInput) {
    requireGrcPermission(user, "MANAGE_RISKS");
    await this.mustFindRisk(workspaceId, riskId);
    const row = await this.prisma.riskReview.create({
      data: {
        workspaceId, riskId, reviewerId: user.id, decision: input.decision,
        changes: input.changes ?? "", nextReviewAt: input.nextReviewAt ? new Date(input.nextReviewAt) : null,
      },
    });
    if (input.nextReviewAt) {
      await this.prisma.riskRecord.update({ where: { id: riskId }, data: { reviewDate: new Date(input.nextReviewAt) } });
    }
    if (input.decision === "CLOSED") {
      await this.prisma.riskRecord.update({ where: { id: riskId }, data: { status: "CLOSED" } });
    }
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "RISK_UPDATED", resourceType: "RiskReview", resourceId: row.id, metadata: { riskId, decision: input.decision },
    });
    return row;
  }

  /** §55: technical risk exceptions (RiskException) surfaced read-only
   *  alongside the register — the VM lifecycle stays authoritative. */
  async listTechnicalExceptions(user: RequestUser, workspaceId: string) {
    requireGrcPermission(user, "VIEW_RISK_REGISTER");
    const items = await this.prisma.riskException.findMany({
      where: { workspaceId }, orderBy: { createdAt: "desc" }, take: 200,
    });
    return { items, total: items.length };
  }

  private async mustFindRisk(workspaceId: string, id: string) {
    const row = await this.prisma.riskRecord.findFirst({ where: { id, workspaceId } });
    if (!row) throw new NotFoundException("Risk not found in this workspace");
    return row;
  }
}

export { bandForScore };
