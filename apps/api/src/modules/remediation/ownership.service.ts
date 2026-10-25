import { Inject, Injectable } from "@nestjs/common";
import { resolveRemediationOwnership as resolveOwnership, type OwnershipInputs } from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { CaseStateService, type FindingRow } from "./case-state.service";
import { requireRemediationPermission } from "./permissions";

/**
 * Ownership + assignment (Prompt 31 §14–§20). Resolution is the SDK's
 * deterministic chain fed from real rows: the finding's own assignment,
 * repository ownership (P12), asset ownership (P5) and the workspace
 * default team. Every (re)assignment is a new RemediationAssignment row
 * — history is preserved, never edited (§20). AI may SUGGEST (§17); a
 * suggestion is data for a human, it assigns nothing by itself.
 */
@Injectable()
export class OwnershipService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly cases: CaseStateService,
  ) {}

  async gatherInputs(workspaceId: string, finding: FindingRow): Promise<OwnershipInputs> {
    const inputs: OwnershipInputs = {};
    if (finding.assignedToId) {
      inputs.explicitAssignment = { ownerType: "USER", ownerId: finding.assignedToId };
    } else if (finding.assignedToTeam) {
      inputs.explicitAssignment = { ownerType: "TEAM", teamId: finding.assignedToTeam };
    }
    // Repository/asset owner steps (§15): this deployment's
    // SourceRepository and Asset models carry no owner fields, so those
    // chain steps honestly resolve to nothing today — the SDK chain
    // supports them the moment the data exists. Resolution therefore
    // rests on the explicit assignment and the workspace default.
    const settings = await this.prisma.workspace.findFirst({ where: { id: workspaceId } });
    const defaultTeam = (settings as unknown as { defaultRemediationTeamId?: string } | null)?.defaultRemediationTeamId;
    if (defaultTeam) inputs.workspaceDefaultTeam = { ownerType: "TEAM", teamId: defaultTeam };
    return inputs;
  }

  async resolveForFinding(workspaceId: string, finding: FindingRow) {
    return resolveOwnership(await this.gatherInputs(workspaceId, finding));
  }

  /** Assign or reassign (§19/§20). Moving an unassigned case to
   *  ASSIGNED is the state transition; reassigning an already-owned
   *  case keeps its status and appends history. */
  async assign(
    user: RequestUser,
    workspaceId: string,
    caseId: string,
    input: { ownerType: string; ownerId?: string; teamId?: string; reason?: string; source?: string },
  ) {
    requireRemediationPermission(user, "ASSIGN_REMEDIATION");
    const kase = await this.cases.getCase(workspaceId, caseId);
    const isFirst = !kase.ownerId && !kase.teamId;
    const assignment = await this.prisma.remediationAssignment.create({
      data: {
        caseId, workspaceId, ownerType: input.ownerType,
        ownerId: input.ownerId ?? null, teamId: input.teamId ?? null,
        confidence: input.source === "MANUAL" ? "VERIFIED" : (kase.ownershipConfidence ?? null),
        assignedBy: user.id, reason: input.reason ?? null, source: input.source ?? "MANUAL",
      },
    });
    const extraData = { ownerType: input.ownerType, ownerId: input.ownerId ?? null, teamId: input.teamId ?? null };
    let updated = kase;
    if (isFirst && ["NEW", "TRIAGED", "REOPENED", "PLANNED"].includes(kase.status)) {
      updated = await this.cases.transition(user, workspaceId, kase, {
        to: "ASSIGNED", reason: input.reason, extraData,
        event: "REMEDIATION_ASSIGNED",
      });
    } else {
      updated = await this.prisma.remediationCase.update({ where: { id: caseId }, data: extraData as never }) as never;
      await this.prisma.remediationStatusHistory.create({
        data: {
          caseId, workspaceId, fromStatus: kase.status, toStatus: kase.status,
          actorId: user.id, reason: input.reason ?? "reassignment", evidence: { reassignment: true } as never,
        },
      });
      await this.cases.emit(user, workspaceId, kase, isFirst ? "REMEDIATION_ASSIGNED" : "REMEDIATION_REASSIGNED", { assignmentId: assignment.id });
    }
    // Mirror onto the finding's assignment fields (P11) so the VM views
    // and the case never disagree about who owns the work.
    await this.prisma.finding.update({
      where: { id: kase.findingId },
      data: {
        assignedToId: input.ownerId ?? null, assignedToTeam: input.teamId ?? null,
        assignedBy: user.id, assignedAt: new Date(),
      } as never,
    });
    return { case: updated, assignment };
  }

  /** §17: an AI-style owner suggestion — returned as data, assigned by
   *  nobody. The endpoint exists so the copilot's suggestion has a
   *  governed shape; applying it still requires ASSIGN_REMEDIATION. */
  async suggestOwner(workspaceId: string, caseId: string) {
    const kase = await this.cases.getCase(workspaceId, caseId);
    const finding = await this.cases.getFinding(workspaceId, kase.findingId);
    const resolution = await this.resolveForFinding(workspaceId, finding);
    return {
      suggestion: resolution.ownerId || resolution.teamId ? resolution : null,
      confidence: resolution.confidence,
      source: resolution.source,
      assigned: false,
      note: "suggestions never assign sensitive remediation ownership (§17) — a human with ASSIGN_REMEDIATION confirms",
    };
  }
}
