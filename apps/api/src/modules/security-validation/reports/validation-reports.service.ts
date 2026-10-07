import { Inject, Injectable } from "@nestjs/common";
import {
  buildProofOfValidation,
  reportClassFor,
  type ValidationOutcome,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireValidationPermission } from "../permissions";
import { ValidationWorkflowService } from "../workflows/validation-workflow.service";

/**
 * Validation reporting (Prompt 16 §60/§61). Reports distinguish
 * Scanner Detected / Safely Validated / Manually Validated / Not
 * Reproduced / Inconclusive — a finding's detection provenance is
 * never blurred into a validation claim. Proof-of-validation summaries
 * are generated from the stored session + sanitized evidence only.
 */
@Injectable()
export class ValidationReportsService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly workflows: ValidationWorkflowService,
  ) {}

  /** §60: per-finding classification counts for the workspace. */
  async classificationSummary(workspaceId: string) {
    const findings = await this.prisma.finding.findMany({
      where: { workspaceId, duplicateOfId: null },
      select: { id: true, validationConfidence: true },
      take: 5000,
    });
    const manual = await this.prisma.manualValidationRecord.findMany({
      where: { workspaceId, outcome: "VERIFIED" },
      select: { findingId: true },
    });
    const manualVerified = new Set(manual.map((m) => m.findingId));
    const latestOutcomes = await this.prisma.validationRequest.findMany({
      where: { workspaceId },
      select: { findingId: true, outcome: true, createdAt: true },
      orderBy: { createdAt: "desc" },
      take: 5000,
    });
    const lastOutcomeByFinding = new Map<string, string>();
    for (const r of latestOutcomes) {
      if (!lastOutcomeByFinding.has(r.findingId) && r.outcome) lastOutcomeByFinding.set(r.findingId, r.outcome);
    }
    const counts: Record<string, number> = {
      SCANNER_DETECTED: 0, SAFELY_VALIDATED: 0, MANUALLY_VALIDATED: 0, NOT_REPRODUCED: 0, INCONCLUSIVE: 0,
    };
    for (const f of findings) {
      const cls = reportClassFor({
        validationConfidence: f.validationConfidence,
        hasManualVerified: manualVerified.has(f.id),
        lastOutcome: lastOutcomeByFinding.get(f.id) ?? null,
      });
      counts[cls] = (counts[cls] ?? 0) + 1;
    }
    return { totalFindings: findings.length, counts };
  }

  /** §61: concise proof-of-validation for one completed request. */
  async proofOfValidation(user: RequestUser, workspaceId: string, requestId: string) {
    requireValidationPermission(user, "VIEW_VALIDATION_EVIDENCE");
    const request = await this.workflows.getValidation(workspaceId, requestId);
    const session = request.sessions[0];
    const ctx = await this.workflows.loadFindingContext(workspaceId, request.findingId);
    const targetDescription = ctx.target ? `${ctx.target.name} (${ctx.target.value})` : request.targetId;
    const proof = buildProofOfValidation({
      findingTitle: ctx.finding.title,
      targetDescription,
      validatorName: request.validatorSlug,
      validationType: request.validationType,
      startedAt: session?.startedAt ? new Date(session.startedAt).toISOString() : request.createdAt.toISOString(),
      endedAt: session?.endedAt ? new Date(session.endedAt).toISOString() : request.updatedAt.toISOString(),
      outcome: (request.outcome as ValidationOutcome) ?? "INCONCLUSIVE",
      evidence: request.evidence.map((e) => ({ type: e.type, checksum: e.checksum })),
    });
    return { requestId, status: request.status, outcome: request.outcome, proof };
  }
}
