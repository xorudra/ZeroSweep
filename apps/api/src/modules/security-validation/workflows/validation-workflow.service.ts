import {
  BadRequestException, ConflictException, HttpException, Inject, Injectable, NotFoundException,
} from "@nestjs/common";
import {
  ScopeMatcher,
  ValidationPlanError,
  ValidationRateLimiter,
  buildValidationPlan,
  clampValidationBudget,
  classifyTechnique,
  evaluateValidationPolicy,
  getValidator,
  validatorsForFinding,
  type ValidationBudget,
  type ValidationFindingView,
} from "@dsrclone/security-sdk";
import { scopeRulesSchema, type ScopeRules } from "@dsrclone/validation";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import { QueueService } from "../../../queue/queue.service";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireValidationPermission } from "../permissions";
import { ValidationPoliciesService } from "../policies/policies.service";

const ACTIVE_STATUSES = ["REQUESTED", "POLICY_REVIEW", "APPROVAL_REQUIRED", "APPROVED", "RUNNING"];
const CANCELLABLE_STATUSES = [...ACTIVE_STATUSES];
const REQUEST_TTL_MS = 24 * 3600_000;

/**
 * Validation workflow (Prompt 16 §3/§10/§13/§51–§53). Creating a
 * request: resolves a governed catalog validator for the finding,
 * snapshots authorization + scope immutably (§8), builds the plan and
 * binds it by content hash (§10), clamps the budget to administrator
 * hard limits (§41), evaluates the ValidationPolicyEngine (§7), and
 * persists the outcome — ALLOW dispatches to the worker queue,
 * REQUIRE_APPROVAL parks the request for a specific human approval,
 * DENY persists a BLOCKED record so denials stay auditable (§54/§82).
 * Prohibited techniques are refused before any of this (§95).
 */
@Injectable()
export class ValidationWorkflowService {
  private readonly rateLimiter = new ValidationRateLimiter();

  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly queue: QueueService,
    private readonly policies: ValidationPoliciesService,
  ) {}

  /** Load a finding with everything validation needs, tenant-scoped. */
  async loadFindingContext(workspaceId: string, findingId: string) {
    const finding = await this.prisma.finding.findFirst({ where: { id: findingId, workspaceId } });
    if (!finding) throw new NotFoundException("finding not found in this workspace (§94)");
    const scan = await this.prisma.scan.findUnique({
      where: { id: finding.scanId },
      include: { assessment: { include: { target: true, scope: true } } },
    });
    const assessment = scan?.assessment;
    const target = assessment?.target;
    const asset = finding.assetId ? await this.prisma.asset.findUnique({ where: { id: finding.assetId } }) : null;
    const scopeRules: ScopeRules = scopeRulesSchema.parse(assessment?.scope?.rules ?? {});
    const view: ValidationFindingView = {
      id: finding.id, title: finding.title, fingerprint: finding.fingerprint,
      vulnClass: finding.vulnClass, cwe: finding.cwe, cve: finding.cve,
      host: finding.host, port: finding.port, endpoint: finding.endpoint,
      sources: finding.sources, assetCriticality: asset?.criticality ?? null,
      repositoryId: finding.repositoryId, filePath: finding.filePath, ruleId: finding.ruleId,
      componentPurl: finding.componentPurl, imageDigest: finding.imageDigest, clusterRef: finding.clusterRef,
      cloudProvider: finding.cloudProvider, cloudResourceId: finding.cloudResourceId,
      directoryDomainId: finding.directoryDomainId, directoryObjectId: finding.directoryObjectId,
    };
    return { finding, view, scan, assessment, target, asset, scopeRules };
  }

  async createValidation(user: RequestUser, workspaceId: string, input: {
    findingId: string;
    validatorSlug?: string;
    technique?: string;
    reason?: string;
    parameters?: Record<string, unknown>;
    budget?: Partial<ValidationBudget>;
    idempotencyKey?: string;
    allowDuplicate?: boolean;
    environment?: string;
  }) {
    requireValidationPermission(user, "REQUEST_SECURITY_VALIDATION");

    // §95: a prohibited technique is refused outright — classified
    // PROHIBITED_AUTOMATION, audited, never persisted as a plan.
    const requestedTechnique = input.validatorSlug ?? input.technique;
    if (requestedTechnique && classifyTechnique(requestedTechnique) === "PROHIBITED_AUTOMATION") {
      await this.audit.record({
        actorId: user.id, organizationId: user.organizationId, workspaceId,
        action: "VALIDATION_BLOCKED", resourceType: "Finding", resourceId: input.findingId,
        metadata: { technique: requestedTechnique, reasonCode: "PROHIBITED_AUTOMATION" },
      });
      throw new BadRequestException(
        `"${requestedTechnique}" is PROHIBITED_AUTOMATION — it can never be planned, approved or executed by this engine (§95/§97). Use a manual validation record (§32) for analyst-performed checks.`,
      );
    }

    const ctx = await this.loadFindingContext(workspaceId, input.findingId);
    if (!ctx.target || !ctx.assessment) throw new BadRequestException("finding has no assessment/target context to validate against");

    // Resolve the governed validator (§68): explicit slug must exist
    // in the catalog and support the finding; otherwise pick the first
    // catalog validator that does.
    let validator = requestedTechnique ? getValidator(requestedTechnique) : undefined;
    if (requestedTechnique && !validator) {
      throw new BadRequestException(`"${requestedTechnique}" is not a governed catalog validator — arbitrary techniques cannot be validated (§68/§79)`);
    }
    if (!validator) {
      validator = validatorsForFinding(ctx.view)[0];
      if (!validator) throw new BadRequestException("no safe validation exists in the catalog for this finding (§6)");
    }
    if (!validator.supportsFinding(ctx.view)) {
      throw new BadRequestException(`validator ${validator.slug} does not support this finding`);
    }

    // §52: idempotency — a replayed key returns the original request.
    if (input.idempotencyKey) {
      const existing = await this.prisma.validationRequest.findFirst({
        where: { workspaceId, idempotencyKey: input.idempotencyKey },
      });
      if (existing) return { ...existing, idempotentReplay: true };
    }

    // §51: no duplicate simultaneous validations for the same
    // finding + target + validator unless explicitly allowed.
    if (!input.allowDuplicate) {
      const duplicate = await this.prisma.validationRequest.findFirst({
        where: {
          workspaceId, findingId: input.findingId, targetId: ctx.target.id,
          validatorSlug: validator.slug, status: { in: ACTIVE_STATUSES as never },
        },
      });
      if (duplicate) {
        throw new ConflictException(`an identical validation is already active (${duplicate.id}, status ${duplicate.status}) — pass allowDuplicate to override (§51)`);
      }
    }

    // §42: rate limits by workspace, target and validator.
    for (const [dimension, key, limit] of [
      ["workspace", workspaceId, 60],
      ["target", ctx.target.id, 30],
      ["validator", validator.slug, 60],
    ] as const) {
      const verdict = this.rateLimiter.check(dimension, key, limit, 3600);
      if (!verdict.allowed) {
        throw new HttpException(`validation rate limit exceeded for ${dimension} — retry after ${verdict.retryAfterSeconds}s (§42)`, 429);
      }
    }

    const policyView = await this.policies.getPolicy(workspaceId);
    const budget = clampValidationBudget(input.budget, policyView.defaultBudget, policyView.hardLimits);

    // §13/§10: build the governed plan; the hash binds future approvals.
    let plan: ReturnType<typeof buildValidationPlan>;
    try {
      plan = buildValidationPlan({
        validatorSlug: validator.slug, finding: ctx.view, targetId: ctx.target.id,
        parameters: input.parameters ?? {}, budget,
      });
    } catch (e) {
      if (e instanceof ValidationPlanError) throw new BadRequestException(e.message);
      throw e;
    }

    const environment = input.environment === "LAB" ? "LAB" : "PRODUCTION";
    const scopeInScope = ctx.view.host
      ? new ScopeMatcher(ctx.scopeRules).isHostAllowed(ctx.view.host)
      : true; // posture destinations bind via target identity + snapshot (§9 worker re-check)

    // §8: immutable authorization + scope snapshots.
    const authorizationSnapshot = {
      targetId: ctx.target.id,
      targetVerified: Boolean(ctx.target.verified),
      assessmentId: ctx.assessment.id,
      assessmentApproved: ctx.assessment.status === "APPROVED",
      allowedTechniques: [validator.slug],
      scopeRules: ctx.scopeRules,
      capturedAt: new Date().toISOString(),
      capturedBy: user.id,
    };

    // §7: policy evaluation (no approval exists yet at request time).
    const decision = evaluateValidationPolicy({
      policy: policyView,
      environment,
      authorization: { targetVerified: authorizationSnapshot.targetVerified, assessmentApproved: authorizationSnapshot.assessmentApproved },
      scope: { inScope: scopeInScope, reason: "destination outside the approved scope" },
      assetCriticality: ctx.view.assetCriticality,
      technique: validator.slug,
      riskClass: validator.riskClass,
      requestedBy: user.id,
      planHash: plan.planHash,
      targetId: ctx.target.id,
      findingId: input.findingId,
      approval: null,
      now: new Date(),
    });

    const status = decision.decision === "ALLOW" ? "APPROVED" : decision.decision === "REQUIRE_APPROVAL" ? "APPROVAL_REQUIRED" : "BLOCKED";
    const request = await this.prisma.validationRequest.create({
      data: {
        workspaceId, findingId: input.findingId, targetId: ctx.target.id, requestedBy: user.id,
        validatorSlug: validator.slug, validationType: validator.validationType,
        toolSlug: validator.toolSlug, riskClass: validator.riskClass,
        reason: input.reason,
        authorizationSnapshot: authorizationSnapshot as never,
        scopeSnapshot: ctx.scopeRules as never,
        plan: plan.plan as never, planHash: plan.planHash,
        parameters: plan.plan.parameters as never,
        budget: budget as never,
        status: status as never,
        policyDecision: decision.decision, policyReason: `${decision.reasonCode}: ${decision.message}`,
        environment,
        idempotencyKey: input.idempotencyKey,
        expiresAt: new Date(Date.now() + REQUEST_TTL_MS),
      },
    });

    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "VALIDATION_REQUESTED", resourceType: "ValidationRequest", resourceId: request.id,
      metadata: { findingId: input.findingId, targetId: ctx.target.id, validator: validator.slug, riskClass: validator.riskClass },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "VALIDATION_POLICY_EVALUATED", resourceType: "ValidationRequest", resourceId: request.id,
      metadata: { decision: decision.decision, reasonCode: decision.reasonCode, validator: validator.slug, riskClass: validator.riskClass },
    });
    if (decision.decision === "DENY") {
      await this.audit.record({
        actorId: user.id, organizationId: user.organizationId, workspaceId,
        action: "VALIDATION_BLOCKED", resourceType: "ValidationRequest", resourceId: request.id,
        metadata: { reasonCode: decision.reasonCode, message: decision.message },
      });
      return { ...request, enqueued: false };
    }
    if (decision.decision === "REQUIRE_APPROVAL") return { ...request, enqueued: false };

    const enqueued = await this.queue.enqueueValidation({ validationRequestId: request.id, workspaceId });
    return { ...request, enqueued };
  }

  async listValidations(workspaceId: string, filters: { status?: string; findingId?: string; targetId?: string } = {}) {
    return this.prisma.validationRequest.findMany({
      where: {
        workspaceId,
        ...(filters.status ? { status: filters.status as never } : {}),
        ...(filters.findingId ? { findingId: filters.findingId } : {}),
        ...(filters.targetId ? { targetId: filters.targetId } : {}),
      },
      orderBy: { createdAt: "desc" },
      take: 200,
      include: { approvals: { orderBy: { createdAt: "desc" }, take: 3 }, sessions: { orderBy: { createdAt: "desc" }, take: 3 } },
    });
  }

  async getValidation(workspaceId: string, id: string) {
    const request = await this.prisma.validationRequest.findFirst({
      where: { id, workspaceId },
      include: {
        approvals: { orderBy: { createdAt: "desc" } },
        sessions: { orderBy: { createdAt: "desc" } },
        evidence: { orderBy: { createdAt: "desc" }, take: 100 },
      },
    });
    if (!request) throw new NotFoundException("validation request not found in this workspace (§94)");
    return request;
  }

  /** §53: validation history for one finding (detail page). */
  async listForFinding(workspaceId: string, findingId: string) {
    await this.loadFindingContext(workspaceId, findingId);
    return this.prisma.validationRequest.findMany({
      where: { workspaceId, findingId },
      orderBy: { createdAt: "desc" },
      take: 100,
      include: { sessions: { orderBy: { createdAt: "desc" }, take: 5 }, approvals: { orderBy: { createdAt: "desc" }, take: 5 } },
    });
  }

  async cancelValidation(user: RequestUser, workspaceId: string, id: string) {
    requireValidationPermission(user, "CANCEL_VALIDATION");
    const request = await this.getValidation(workspaceId, id);
    if (!CANCELLABLE_STATUSES.includes(request.status)) {
      throw new BadRequestException(`a validation in status ${request.status} cannot be cancelled`);
    }
    // §43: if a session is running, plant a SESSION kill switch so the
    // worker terminates the active process, not just the record.
    const runningSession = request.sessions.find((s) => s.status === "RUNNING");
    if (runningSession) {
      await this.prisma.validationKillSwitch.create({
        data: {
          level: "SESSION", workspaceId, scopeRef: runningSession.id,
          reason: "validation cancelled via API", activatedBy: user.id, active: true,
        },
      });
    }
    const updated = await this.prisma.validationRequest.update({
      where: { id }, data: { status: "CANCELLED" },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "VALIDATION_CANCELLED", resourceType: "ValidationRequest", resourceId: id,
      metadata: { previousStatus: request.status, runningSessionTerminated: Boolean(runningSession) },
    });
    return updated;
  }

  /** §54 dashboard buckets + §82 observability, computed from real rows. */
  async dashboard(workspaceId: string, organizationId: string) {
    const requests = await this.prisma.validationRequest.findMany({ where: { workspaceId }, take: 1000 });
    const sessions = await this.prisma.validationSession.findMany({ where: { workspaceId }, take: 1000 });
    const approvals = await this.prisma.validationApproval.findMany({ where: { workspaceId }, take: 1000 });
    const killSwitches = await this.prisma.validationKillSwitch.count({
      where: { OR: [{ workspaceId }, { organizationId }] },
    });
    const count = (statuses: string[]) => requests.filter((r) => statuses.includes(r.status)).length;
    const terminal = requests.filter((r) => ["SUCCEEDED", "FAILED", "INCONCLUSIVE", "BLOCKED"].includes(r.status));
    const succeeded = count(["SUCCEEDED"]);
    const durations = sessions
      .filter((s) => s.startedAt && s.endedAt)
      .map((s) => (new Date(s.endedAt!).getTime() - new Date(s.startedAt!).getTime()) / 1000);
    const latencies = approvals
      .filter((a) => a.decision === "APPROVED")
      .map((a) => {
        const req = requests.find((r) => r.id === a.requestId);
        return req ? (new Date(a.approvedAt).getTime() - new Date(req.createdAt).getTime()) / 1000 : undefined;
      })
      .filter((v): v is number => v !== undefined);
    const avg = (xs: number[]) => (xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : null);
    return {
      buckets: {
        pending: count(["REQUESTED", "POLICY_REVIEW"]),
        approvalRequired: count(["APPROVAL_REQUIRED"]),
        running: count(["RUNNING"]),
        verified: succeeded,
        inconclusive: count(["INCONCLUSIVE"]),
        blocked: count(["BLOCKED"]),
        failed: count(["FAILED"]),
        expired: count(["EXPIRED"]),
        cancelled: count(["CANCELLED"]),
      },
      metrics: {
        totalRequests: requests.length,
        approvalLatencySeconds: avg(latencies),
        successRate: terminal.length ? succeeded / terminal.length : null,
        inconclusiveRate: terminal.length ? count(["INCONCLUSIVE"]) / terminal.length : null,
        blockedRequests: count(["BLOCKED"]),
        policyDenials: requests.filter((r) => r.policyDecision === "DENY").length,
        averageDurationSeconds: avg(durations),
        budgetExhaustions: sessions.filter((s) => (s.terminationReason ?? "").includes("BUDGET_EXCEEDED")).length,
        killSwitchActivations: killSwitches,
      },
    };
  }
}
