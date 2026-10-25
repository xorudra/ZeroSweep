import { BadRequestException, Inject, Injectable } from "@nestjs/common";
import {
  buildValidationEvidence,
  confidenceUpdateForManualValidation,
  sanitizeEvidenceText,
  sanitizeEvidenceValue,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireValidationPermission } from "../permissions";
import { ValidationWorkflowService } from "../workflows/validation-workflow.service";

/**
 * Manual validation (Prompt 16 §32). Authorized analysts attach their
 * own evidence — description, sanitized screenshots/logs/request-
 * response excerpts, notes — for validations ZeroSweep must not
 * automate (RCE-class findings, §21, are manual-only). ZeroSweep
 * executes NOTHING for these records. Attachments are sanitized before
 * storage (§34); an analyst's VERIFIED attestation updates the finding
 * through the same confidence path as automated validation (§36).
 */
@Injectable()
export class ManualValidationService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly workflows: ValidationWorkflowService,
  ) {}

  async addManualValidation(user: RequestUser, workspaceId: string, findingId: string, input: {
    description: string;
    outcome?: string;
    evidence?: Record<string, unknown>;
    notes?: string;
  }) {
    requireValidationPermission(user, "ADD_MANUAL_VALIDATION");
    if (!input.description?.trim()) throw new BadRequestException("a manual validation record requires a description (§32)");
    const outcome = input.outcome === "VERIFIED" || input.outcome === "NOT_REPRODUCED" ? input.outcome : "INCONCLUSIVE";
    await this.workflows.loadFindingContext(workspaceId, findingId); // tenant isolation (§94)

    // Sanitize attachments through the evidence pipeline (§34): the
    // record stores the sanitized artifact + its checksum (§35).
    const sanitized = buildValidationEvidence({
      type: "MANUAL_NOTE",
      summary: input.description,
      content: {
        ...(input.evidence ? { attachments: sanitizeEvidenceValue(input.evidence) as Record<string, unknown> } : {}),
        ...(input.notes ? { notes: sanitizeEvidenceText(input.notes) } : {}),
      },
    });
    const record = await this.prisma.manualValidationRecord.create({
      data: {
        workspaceId, findingId, analystId: user.id,
        description: sanitized.summary,
        outcome,
        evidence: { checksum: sanitized.checksum, content: sanitized.content ?? null } as never,
      },
    });

    const update = confidenceUpdateForManualValidation(outcome);
    await this.prisma.finding.update({
      where: { id: findingId },
      data: {
        validationConfidence: update.validationConfidence,
        ...(update.verificationStatus ? { verificationStatus: update.verificationStatus } : {}),
        lastValidatedAt: new Date(update.lastValidatedAt),
      },
    });
    await this.prisma.findingHistory.create({
      data: {
        findingId, workspaceId, actorId: user.id, event: "MANUAL_VALIDATION",
        metadata: { manualValidationId: record.id, outcome, note: update.note } as never,
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "MANUAL_VALIDATION_ADDED", resourceType: "Finding", resourceId: findingId,
      metadata: { manualValidationId: record.id, outcome },
    });
    return record;
  }

  async listForFinding(user: RequestUser, workspaceId: string, findingId: string) {
    requireValidationPermission(user, "VIEW_VALIDATION_EVIDENCE");
    await this.workflows.loadFindingContext(workspaceId, findingId);
    return this.prisma.manualValidationRecord.findMany({
      where: { workspaceId, findingId },
      orderBy: { createdAt: "desc" },
      take: 100,
    });
  }
}
