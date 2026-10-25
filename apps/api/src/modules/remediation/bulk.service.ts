import { BadRequestException, Injectable } from "@nestjs/common";
import { BULK_REMEDIATION_ACTIONS, BULK_REMEDIATION_MAX_ITEMS, type BulkRemediationAction } from "@zerosweep/security-sdk";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { CaseStateService } from "./case-state.service";
import { OwnershipService } from "./ownership.service";
import { RemediationSlaService } from "./sla.service";
import { RemediationTicketsService } from "./tickets.service";
import { RemediationVerificationService } from "./verification.service";
import { requireRemediationPermission } from "./permissions";

/**
 * Bulk actions (Prompt 31 §84–§86). The action set is the SDK's closed
 * list — VERIFY/CLOSE is not in it, so bulk verification or bulk
 * closure is structurally impossible, not just discouraged (§147).
 * Every bulk run needs a preview + explicit confirmation (§85) and is
 * capped; each item's outcome is reported individually.
 */
@Injectable()
export class RemediationBulkService {
  constructor(
    private readonly state: CaseStateService,
    private readonly ownership: OwnershipService,
    private readonly sla: RemediationSlaService,
    private readonly tickets: RemediationTicketsService,
    private readonly verification: RemediationVerificationService,
  ) {}

  async bulk(user: RequestUser, workspaceId: string, input: {
    action: string; caseIds: string[]; confirm?: boolean;
    ownerType?: string; ownerId?: string; teamId?: string;
    provider?: string; verificationMethod?: string;
  }) {
    if (!(BULK_REMEDIATION_ACTIONS as readonly string[]).includes(input.action)) {
      throw new BadRequestException(
        `bulk action ${input.action} is not permitted — allowed: ${BULK_REMEDIATION_ACTIONS.join(", ")}. Bulk VERIFIED_FIXED/CLOSED is rejected (§86/§147).`,
      );
    }
    if (!input.caseIds?.length) throw new BadRequestException("caseIds is required");
    if (input.caseIds.length > BULK_REMEDIATION_MAX_ITEMS) {
      throw new BadRequestException(`bulk operations are capped at ${BULK_REMEDIATION_MAX_ITEMS} items (§84)`);
    }
    const action = input.action as BulkRemediationAction;
    // Preview (§85): resolve every case first so the operator sees
    // exactly what will be touched before confirming.
    const preview: Array<{ caseId: string; status: string; findingId: string }> = [];
    for (const caseId of input.caseIds) {
      const kase = await this.state.getCase(workspaceId, caseId);
      preview.push({ caseId, status: kase.status, findingId: kase.findingId });
    }
    if (!input.confirm) {
      return { preview, requiresConfirmation: true, applied: 0 };
    }
    const results: Array<{ caseId: string; ok: boolean; detail: string }> = [];
    for (const caseId of input.caseIds) {
      try {
        if (action === "ASSIGN") {
          requireRemediationPermission(user, "ASSIGN_REMEDIATION");
          await this.ownership.assign(user, workspaceId, caseId, {
            ownerType: input.ownerType ?? "TEAM", ownerId: input.ownerId, teamId: input.teamId,
            reason: "bulk assignment", source: "BULK",
          });
          results.push({ caseId, ok: true, detail: "assigned" });
        } else if (action === "CREATE_TICKETS") {
          await this.tickets.createTicket(user, workspaceId, caseId, { provider: input.provider ?? "JIRA" });
          results.push({ caseId, ok: true, detail: "work item created" });
        } else if (action === "APPLY_SLA_POLICY") {
          await this.sla.assignSla(user, workspaceId, caseId);
          results.push({ caseId, ok: true, detail: "SLA assigned" });
        } else if (action === "REQUEST_VERIFICATION") {
          await this.verification.requestVerification(user, workspaceId, caseId, {
            method: (input.verificationMethod ?? "TARGETED_RETEST") as never,
          });
          results.push({ caseId, ok: true, detail: "verification requested" });
        }
      } catch (err) {
        results.push({ caseId, ok: false, detail: err instanceof Error ? err.message : "failed" });
      }
    }
    return { preview, requiresConfirmation: false, applied: results.filter((r) => r.ok).length, results };
  }
}
