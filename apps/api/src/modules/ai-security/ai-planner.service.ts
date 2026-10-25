import { BadRequestException, ForbiddenException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import { createHash } from "node:crypto";
import {
  AI_SAFE_DEFAULT_PROFILE, AI_TOOL_CATALOG, authorizationSnapshotHash, canTransitionWorkflow,
  evaluateAiApproval, planAutomaticAnalysis, validateAiPlan,
  type AiAuthorizationSnapshot, type AiPlanStep, type AiRiskClass, type AiSecurityPlan,
} from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { AuditService } from "../audit/audit.service";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { aiPermissionsHeld, requireAiPermission } from "./permissions";
import { AiConfigService } from "./ai-config.service";
import { AiGatewayService } from "./ai-gateway.service";
import { AiCopilotService } from "./ai-copilot.service";

const RISK_ORDER: AiRiskClass[] = ["NONE", "LOW", "MEDIUM", "HIGH", "CRITICAL"];
const maxRisk = (steps: AiPlanStep[]): AiRiskClass =>
  steps.reduce((acc, s) => (RISK_ORDER.indexOf(s.riskClass) > RISK_ORDER.indexOf(acc) ? s.riskClass : acc), "NONE" as AiRiskClass);

/**
 * SecurityAiPlanner + workflow service (Prompt 36 §41–§50). Plans
 * are composed deterministically from gateway capabilities and
 * approved profiles (§74/§75 — "scan this" defaults to the safe
 * baseline, §77), validated by the SDK's deterministic validator
 * against the CURRENT immutable authorization snapshot (§43/§46),
 * and only a human can approve them (§48/§49) with separation of
 * duties (§143) and expiry (§50). Execution hands steps to the tool
 * gateway / owning workflows — the AI executes nothing itself, and
 * if validation cannot run the workflow fails closed (§150).
 */
@Injectable()
export class AiPlannerService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly config: AiConfigService,
    private readonly gateway: AiGatewayService,
    private readonly copilot: AiCopilotService,
  ) {}

  /** Build the authorization snapshot from the platform's own
   *  authorization records: VERIFIED targets + APPROVED assessments.
   *  The snapshot is a read model — building it mutates nothing. */
  async buildAuthorizationSnapshot(workspaceId: string): Promise<AiAuthorizationSnapshot> {
    const targets = await this.prisma.target.findMany({ where: { workspaceId }, take: 500 });
    const rows: AiAuthorizationSnapshot["targets"] = [];
    for (const t of targets as Record<string, unknown>[]) {
      const approved = await this.prisma.assessment.findFirst({ where: { targetId: t.id as string, workspaceId, status: "APPROVED" } });
      rows.push({ targetId: t.id as string, verified: t.verified === true, assessmentApproved: !!approved });
    }
    const scopeHash = createHash("sha256")
      .update(JSON.stringify(rows.map((r) => `${r.targetId}:${r.verified}:${r.assessmentApproved}`).sort()))
      .digest("hex");
    return {
      snapshotId: `snap-${scopeHash.slice(0, 16)}`,
      workspaceId,
      targets: rows,
      scopeHash,
      capturedAt: new Date().toISOString(),
    };
  }

  private composePlan(body: {
    taskType?: string; objective?: string; targetIds?: string[]; profile?: string;
    findingId?: string; incidentId?: string;
  }): { plan: AiSecurityPlan; mode: string } {
    const taskType = body.taskType ?? "SCAN_PLAN_DRAFT";
    const steps: AiPlanStep[] = [];
    let mode = "PLANNING";
    if (taskType === "SCAN_PLAN_DRAFT") {
      steps.push({
        id: "step-1", objective: body.objective ?? "Assess the authorized application",
        capability: "draftScanPlan", targetReferences: body.targetIds ?? [], dependencies: [],
        riskClass: "MEDIUM", requiredPermission: "CREATE_AI_PLAN", approvalRequired: true,
        expectedEvidence: ["scan record", "normalized findings"], scanProfile: body.profile ?? AI_SAFE_DEFAULT_PROFILE,
      });
      steps.push({
        id: "step-2", objective: "Record a scan draft through the governed orchestration intake",
        capability: "createScanDraft", targetReferences: body.targetIds ?? [], dependencies: ["step-1"],
        riskClass: "MEDIUM", requiredPermission: "RUN_AI_APPROVED_ACTION", approvalRequired: true,
        expectedEvidence: ["scan draft id"],
      });
    } else if (taskType === "VERIFICATION_PLAN") {
      mode = "APPROVAL_REQUIRED_ACTION";
      steps.push({
        id: "step-1", objective: "Draft a minimal targeted verification plan",
        capability: "draftVerificationPlan", targetReferences: [], dependencies: [],
        riskClass: "MEDIUM", requiredPermission: "CREATE_AI_PLAN", approvalRequired: true,
        expectedEvidence: ["verification plan"],
      });
      steps.push({
        id: "step-2", objective: "Request verification through the Prompt 31 workflow",
        capability: "requestVerification", targetReferences: [], dependencies: ["step-1"],
        riskClass: "LOW", requiredPermission: "AI_PROPOSE_ACTION", approvalRequired: false,
        expectedEvidence: ["verification request proposal"],
      });
    } else if (taskType === "REMEDIATION_PLAN") {
      steps.push({
        id: "step-1", objective: "Draft remediation guidance for the finding",
        capability: "draftRemediationPlan", targetReferences: [], dependencies: [],
        riskClass: "LOW", requiredPermission: "CREATE_AI_PLAN", approvalRequired: false,
        expectedEvidence: ["remediation draft"],
      });
    } else if (taskType === "INVESTIGATION_PLAN") {
      steps.push({
        id: "step-1", objective: "Draft an SOC investigation plan",
        capability: "draftInvestigationPlan", targetReferences: [], dependencies: [],
        riskClass: "LOW", requiredPermission: "CREATE_AI_PLAN", approvalRequired: false,
        expectedEvidence: ["investigation plan"],
      });
    } else {
      throw new BadRequestException(`taskType ${taskType} does not produce a plan — supported: SCAN_PLAN_DRAFT, VERIFICATION_PLAN, REMEDIATION_PLAN, INVESTIGATION_PLAN`);
    }
    return {
      mode,
      plan: {
        objective: body.objective ?? taskType, taskType, workspaceId: "",
        authorizationSnapshotHash: "", steps,
      },
    };
  }

  async createPlan(user: RequestUser, workspaceId: string, body: {
    taskType?: string; objective?: string; targetIds?: string[]; profile?: string; findingId?: string; incidentId?: string;
  }) {
    requireAiPermission(user, "CREATE_AI_PLAN");
    const snapshot = await this.buildAuthorizationSnapshot(workspaceId);
    const { plan, mode } = this.composePlan(body);
    plan.workspaceId = workspaceId;
    plan.authorizationSnapshotHash = authorizationSnapshotHash(snapshot);
    // Plan-level context carried for the gateway at execution time.
    (plan as unknown as Record<string, unknown>).context = { findingId: body.findingId ?? null, incidentId: body.incidentId ?? null };

    const budget = await this.config.getBudget(workspaceId);
    const validation = validateAiPlan(plan, {
      userPermissions: aiPermissionsHeld(user),
      snapshot,
      availableTools: AI_TOOL_CATALOG.map((t) => t.name),
      budgetRemainingTokens: budget.monthlyTokenLimit,
      estimatedPlanTokens: 1000,
      riskCeilingWithoutApproval: "MEDIUM",
      hasApproval: false,
    });

    const needsApproval = plan.steps.some((s) => s.approvalRequired);
    const status = validation.verdict === "REJECTED" ? "REJECTED"
      : validation.verdict === "REQUIRE_MODIFICATION" ? "DRAFT"
      : needsApproval ? "AWAITING_APPROVAL" : "APPROVED";
    // Note: approval-required steps validate as VALID with
    // APPROVAL_PENDING findings (§48) — the workflow then waits in
    // AWAITING_APPROVAL; execution re-validates with the approval.

    const workflow = await this.prisma.aiSecurityWorkflow.create({
      data: {
        workspaceId, requestedBy: user.id, taskType: plan.taskType, objective: plan.objective,
        mode, status, plan: plan as never, validation: validation as never,
        authorizationSnapshotHash: plan.authorizationSnapshotHash,
        maxSteps: 8, maxTokens: budget.perTaskTokenLimit,
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: validation.verdict === "REJECTED" ? "AI_PLAN_REJECTED" : "AI_PLAN_CREATED",
      resourceType: "AiSecurityWorkflow", resourceId: workflow.id,
      metadata: { taskType: plan.taskType, verdict: validation.verdict, findings: validation.findings.length },
    });
    if (status === "AWAITING_APPROVAL") {
      const approval = await this.prisma.aiActionApproval.create({
        data: {
          workspaceId, workflowId: workflow.id, stepId: null, requestedBy: user.id,
          reason: `Approve AI plan "${plan.objective}" (${plan.taskType})`,
          riskClass: maxRisk(plan.steps), scope: { targetIds: body.targetIds ?? [], profile: body.profile ?? null },
          decision: "PENDING", expiresAt: new Date(Date.now() + 24 * 3600000),
        },
      });
      await this.audit.record({
        actorId: user.id, organizationId: user.organizationId, workspaceId,
        action: "AI_ACTION_APPROVAL_REQUESTED", resourceType: "AiActionApproval", resourceId: approval.id,
        metadata: { workflowId: workflow.id, riskClass: maxRisk(plan.steps) },
      });
      return { workflow, approval, validation, executed: false as const };
    }
    return { workflow, approval: null, validation, executed: false as const };
  }

  async listPlans(user: RequestUser, workspaceId: string) {
    requireAiPermission(user, "USE_AI_COPILOT");
    return this.prisma.aiSecurityWorkflow.findMany({ where: { workspaceId }, orderBy: { createdAt: "desc" }, take: 100 });
  }

  async getPlan(user: RequestUser, workspaceId: string, id: string) {
    requireAiPermission(user, "USE_AI_COPILOT");
    const workflow = await this.prisma.aiSecurityWorkflow.findFirst({ where: { id, workspaceId } });
    if (!workflow) throw new NotFoundException("plan/workflow not found in this workspace");
    const approvals = await this.prisma.aiActionApproval.findMany({ where: { workflowId: id, workspaceId }, orderBy: { createdAt: "asc" } });
    return { workflow, approvals };
  }

  async listApprovals(user: RequestUser, workspaceId: string) {
    requireAiPermission(user, "APPROVE_AI_ACTION");
    return this.prisma.aiActionApproval.findMany({ where: { workspaceId }, orderBy: { createdAt: "desc" }, take: 100 });
  }

  private async decide(user: RequestUser, workspaceId: string, workflowId: string, decision: "APPROVED" | "REJECTED") {
    requireAiPermission(user, "APPROVE_AI_ACTION");
    const workflow = await this.prisma.aiSecurityWorkflow.findFirst({ where: { id: workflowId, workspaceId } });
    if (!workflow) throw new NotFoundException("workflow not found in this workspace");
    const approval = await this.prisma.aiActionApproval.findFirst({
      where: { workflowId, workspaceId, decision: "PENDING" }, orderBy: { createdAt: "desc" },
    });
    if (!approval) throw new BadRequestException("no pending approval exists for this workflow");
    const policy = await this.prisma.aiWorkspacePolicy.findFirst({ where: { workspaceId } });
    const evaluation = evaluateAiApproval({
      requestedBy: approval.requestedBy, approverId: user.id, approverIsAi: false,
      decision, expiresAt: (approval.expiresAt as Date).toISOString(), now: new Date(),
      separationOfDuties: (policy?.approvalPolicy ?? "SOD_RESTRICTED") === "SOD_RESTRICTED",
      riskClass: (approval.riskClass as AiRiskClass) ?? "LOW",
    });
    if (!evaluation.accepted) {
      await this.audit.record({
        actorId: user.id, organizationId: user.organizationId, workspaceId,
        action: "AI_POLICY_BLOCKED", resourceType: "AiActionApproval", resourceId: approval.id,
        metadata: { reason: evaluation.reason },
      });
      throw new ForbiddenException(evaluation.reason);
    }
    await this.prisma.aiActionApproval.update({
      where: { id: approval.id },
      data: { decision, approvedBy: user.id, approvedAt: new Date() },
    });
    const nextStatus = decision === "APPROVED" ? "APPROVED" : "REJECTED";
    if (!canTransitionWorkflow(workflow.status as never, nextStatus as never)) {
      throw new BadRequestException(`workflow in state ${workflow.status} cannot transition to ${nextStatus} (§47)`);
    }
    const updated = await this.prisma.aiSecurityWorkflow.update({ where: { id: workflowId }, data: { status: nextStatus } });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: decision === "APPROVED" ? "AI_ACTION_APPROVED" : "AI_ACTION_REJECTED",
      resourceType: "AiActionApproval", resourceId: approval.id, metadata: { workflowId },
    });
    return { workflow: updated, approval: { ...approval, decision, approvedBy: user.id }, executed: false as const };
  }

  async approveWorkflow(user: RequestUser, workspaceId: string, workflowId: string) {
    return this.decide(user, workspaceId, workflowId, "APPROVED");
  }

  async rejectWorkflow(user: RequestUser, workspaceId: string, workflowId: string) {
    return this.decide(user, workspaceId, workflowId, "REJECTED");
  }

  async executeWorkflow(user: RequestUser, workspaceId: string, workflowId: string) {
    requireAiPermission(user, "RUN_AI_APPROVED_ACTION");
    const workflow = await this.prisma.aiSecurityWorkflow.findFirst({ where: { id: workflowId, workspaceId } });
    if (!workflow) throw new NotFoundException("workflow not found in this workspace");
    if (workflow.status !== "APPROVED") {
      throw new BadRequestException(`workflow must be APPROVED before execution (current: ${workflow.status}) — AI cannot self-approve (§49)`);
    }
    const plan = workflow.plan as unknown as AiSecurityPlan & { context?: { findingId?: string | null; incidentId?: string | null } };

    // §150 fail closed: re-validate against the CURRENT snapshot
    // before anything runs. If validation cannot be performed or the
    // snapshot drifted, the workflow fails — nothing executes.
    let revalidation;
    try {
      const snapshot = await this.buildAuthorizationSnapshot(workspaceId);
      const budget = await this.config.getBudget(workspaceId);
      revalidation = validateAiPlan(plan, {
        userPermissions: aiPermissionsHeld(user), snapshot,
        availableTools: AI_TOOL_CATALOG.map((t) => t.name),
        budgetRemainingTokens: budget.monthlyTokenLimit, estimatedPlanTokens: 1000,
        riskCeilingWithoutApproval: "MEDIUM", hasApproval: true,
      });
    } catch (err) {
      await this.prisma.aiSecurityWorkflow.update({ where: { id: workflowId }, data: { status: "FAILED", completedAt: new Date(), result: { error: `validation unavailable — failed closed (§150): ${(err as Error).message}` } as never } });
      throw new BadRequestException("plan validation unavailable — workflow failed closed, nothing executed (§150)");
    }
    if (revalidation.verdict === "REJECTED") {
      await this.prisma.aiSecurityWorkflow.update({ where: { id: workflowId }, data: { status: "FAILED", completedAt: new Date(), result: { error: "plan no longer validates against the current authorization snapshot", findings: revalidation.findings } as never } });
      await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId, action: "AI_PLAN_REJECTED", resourceType: "AiSecurityWorkflow", resourceId: workflowId, metadata: { stage: "EXECUTION_REVALIDATION" } });
      throw new BadRequestException("plan no longer validates against the current authorization snapshot — nothing executed (§46/§150)");
    }

    await this.prisma.aiSecurityWorkflow.update({ where: { id: workflowId }, data: { status: "RUNNING" } });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId, action: "AI_WORKFLOW_STARTED", resourceType: "AiSecurityWorkflow", resourceId: workflowId, metadata: { taskType: workflow.taskType } });

    const stepResults: { stepId: string; capability: string; verdict: string; summary: string }[] = [];
    let anyBlocked = false;
    for (const step of plan.steps) {
      const args: Record<string, unknown> = {
        objective: step.objective,
        targetIds: step.targetReferences,
        ...(step.scanProfile ? { profile: step.scanProfile } : {}),
        ...(plan.context?.findingId ? { findingId: plan.context.findingId } : {}),
        ...(plan.context?.incidentId ? { incidentId: plan.context.incidentId } : {}),
      };
      const out = await this.gateway.callTool(user, workspaceId, step.capability, args, {
        hasApproval: true, authorizationValid: true, workflowId, skipTrace: true,
      });
      if (out.verdict === "BLOCKED") anyBlocked = true;
      stepResults.push({ stepId: step.id, capability: step.capability, verdict: out.verdict, summary: out.summary });
    }
    const finalStatus = anyBlocked ? "PARTIAL" : "COMPLETED";
    const result = { steps: stepResults, executed: false, note: "steps were handed to governed platform workflows/proposals; the AI executed nothing itself (§26/§33)" };
    const updated = await this.prisma.aiSecurityWorkflow.update({
      where: { id: workflowId },
      data: { status: finalStatus, completedAt: new Date(), result: result as never },
    });
    await this.prisma.aiSecurityTrace.create({
      data: {
        workspaceId, userId: user.id, workflowId, taskType: String(workflow.taskType),
        requestMetadata: { objective: workflow.objective },
        toolCalls: stepResults.map((s) => ({ tool: s.capability, verdict: s.verdict })),
        policyDecisions: [{ stage: "EXECUTION_REVALIDATION", verdict: revalidation.verdict }],
        validationResults: [revalidation as never],
        timings: {},
      },
    });
    await this.audit.record({ actorId: user.id, organizationId: user.organizationId, workspaceId, action: "AI_WORKFLOW_COMPLETED", resourceType: "AiSecurityWorkflow", resourceId: workflowId, metadata: { status: finalStatus, steps: stepResults.length } });
    return { workflow: updated, result, executed: false as const };
  }

  /** §37–§40: autonomous analysis trigger. Produces ANALYSIS work
   *  items only; for finding triggers it runs the governed copilot
   *  explanation. It can never launch a scan or offensive action. */
  async analyzeTrigger(user: RequestUser, workspaceId: string, body: { trigger: string; findingId?: string }) {
    requireAiPermission(user, "USE_AI_COPILOT");
    const item = planAutomaticAnalysis(body.trigger);
    if (!item) throw new BadRequestException(`unknown analysis trigger "${body.trigger}" — only governed analysis triggers exist (§38)`);
    let copilotRequestLogId: string | null = null;
    if (body.findingId && (item.tasks.includes("FINDING_EXPLANATION") || item.tasks.includes("RISK_CONTEXT_SUMMARY"))) {
      const res = await this.copilot.findingTask(user, workspaceId, body.findingId, "FINDING_EXPLANATION");
      copilotRequestLogId = res.requestLogId;
    }
    await this.prisma.aiSecurityTrace.create({
      data: {
        workspaceId, userId: user.id, taskType: "AUTONOMOUS_ANALYSIS",
        requestMetadata: { trigger: item.trigger, tasks: item.tasks },
        policyDecisions: [{ decision: "ANALYSIS_ONLY", offensiveAction: item.offensiveAction }],
        timings: {},
      },
    });
    return { ...item, copilotRequestLogId };
  }
}
