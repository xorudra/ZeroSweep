import { Inject, Injectable } from "@nestjs/common";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireValidationPermission } from "../permissions";
import { ValidationWorkflowService } from "../workflows/validation-workflow.service";

/**
 * Validation evidence access (Prompt 16 §33–§35). Evidence rows were
 * sanitized BEFORE storage (§34) — this service never un-redacts.
 * Every read is permission-checked, tenant-scoped through the parent
 * request, and audited (§80: VALIDATION_EVIDENCE_ACCESSED).
 */
@Injectable()
export class ValidationEvidenceService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly workflows: ValidationWorkflowService,
  ) {}

  async listForRequest(user: RequestUser, workspaceId: string, requestId: string) {
    requireValidationPermission(user, "VIEW_VALIDATION_EVIDENCE");
    await this.workflows.getValidation(workspaceId, requestId); // tenant isolation (§94)
    const evidence = await this.prisma.validationEvidence.findMany({
      where: { requestId, workspaceId },
      orderBy: { createdAt: "asc" },
      take: 200,
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "VALIDATION_EVIDENCE_ACCESSED", resourceType: "ValidationRequest", resourceId: requestId,
      metadata: { evidenceCount: evidence.length },
    });
    return evidence;
  }
}
