import { BadRequestException, ForbiddenException, Inject, Injectable } from "@nestjs/common";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import { QueueService } from "../../../queue/queue.service";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireValidationPermission } from "../permissions";
import { ValidationPoliciesService } from "../policies/policies.service";
import { ValidationWorkflowService } from "../workflows/validation-workflow.service";

/** §63: intrusive approvals (LAB architecture) expire fast. */
const INTRUSIVE_APPROVAL_TTL_MINUTES = 15;

/**
 * Validation approval workflow (Prompt 16 §10/§11). An approval is
 * SPECIFIC: it records the exact plan hash, and thereby binds target +
 * finding + technique. Approving dispatches the request to the worker,
 * which re-verifies hash + expiry again before executing. Separation
 * of duties (§11): for anything above SAFE, the approver must differ
 * from the requester when the workspace policy requires it.
 */
@Injectable()
export class ValidationApprovalsService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly queue: QueueService,
    private readonly policies: ValidationPoliciesService,
    private readonly workflows: ValidationWorkflowService,
  ) {}

  async approve(user: RequestUser, workspaceId: string, id: string, reason?: string) {
    requireValidationPermission(user, "APPROVE_SECURITY_VALIDATION");
    const request = await this.workflows.getValidation(workspaceId, id);
    if (request.status !== "APPROVAL_REQUIRED" && request.status !== "REQUESTED" && request.status !== "POLICY_REVIEW") {
      throw new BadRequestException(`a validation in status ${request.status} cannot be approved`);
    }
    const policy = await this.policies.getPolicy(workspaceId);
    if (policy.separationOfDuties && request.riskClass !== "SAFE" && request.requestedBy === user.id) {
      throw new ForbiddenException("separation of duties: the requester cannot approve their own higher-risk validation (§11)");
    }
    if (request.riskClass === "PROHIBITED_AUTOMATION") {
      throw new BadRequestException("PROHIBITED_AUTOMATION validations can never be approved (§95)");
    }
    const ttlMinutes = request.riskClass === "INTRUSIVE"
      ? Math.min(policy.approvalTtlMinutes, INTRUSIVE_APPROVAL_TTL_MINUTES)
      : policy.approvalTtlMinutes;
    const approval = await this.prisma.validationApproval.create({
      data: {
        requestId: id, workspaceId, approverId: user.id, decision: "APPROVED",
        reason, planHash: request.planHash,
        expiresAt: new Date(Date.now() + ttlMinutes * 60_000),
      },
    });
    await this.prisma.validationRequest.update({ where: { id }, data: { status: "APPROVED" } });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "VALIDATION_APPROVED", resourceType: "ValidationRequest", resourceId: id,
      metadata: {
        findingId: request.findingId, targetId: request.targetId, validator: request.validatorSlug,
        riskClass: request.riskClass, planHash: request.planHash, expiresAt: approval.expiresAt.toISOString(),
      },
    });
    const enqueued = await this.queue.enqueueValidation({ validationRequestId: id, workspaceId });
    return { approval, enqueued };
  }

  async reject(user: RequestUser, workspaceId: string, id: string, reason?: string) {
    requireValidationPermission(user, "APPROVE_SECURITY_VALIDATION");
    const request = await this.workflows.getValidation(workspaceId, id);
    if (request.status !== "APPROVAL_REQUIRED" && request.status !== "REQUESTED" && request.status !== "POLICY_REVIEW") {
      throw new BadRequestException(`a validation in status ${request.status} cannot be rejected`);
    }
    const approval = await this.prisma.validationApproval.create({
      data: {
        requestId: id, workspaceId, approverId: user.id, decision: "REJECTED",
        reason, planHash: request.planHash,
        expiresAt: new Date(),
      },
    });
    await this.prisma.validationRequest.update({
      where: { id },
      data: { status: "BLOCKED", outcome: "VALIDATION_BLOCKED", policyDecision: "DENY", policyReason: `REJECTED_BY_APPROVER: ${reason ?? "no reason given"}` },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "VALIDATION_REJECTED", resourceType: "ValidationRequest", resourceId: id,
      metadata: { findingId: request.findingId, validator: request.validatorSlug, reason: reason ?? null },
    });
    return approval;
  }
}
