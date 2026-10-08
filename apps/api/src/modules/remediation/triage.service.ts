import { BadRequestException, Injectable } from "@nestjs/common";
import { REMEDIATION_TRIAGE_DECISIONS as TRIAGE_DECISIONS, type RemediationTriageDecision as TriageDecision } from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { Inject } from "@nestjs/common";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { CaseStateService } from "./case-state.service";
import { VulnerabilityService } from "../vulnerabilities/vulnerability.service";
import { requireRemediationPermission } from "./permissions";

/**
 * Triage (Prompt 31 §10–§13). Every decision is a preserved record.
 * FALSE_POSITIVE demands reason + evidence and moves BOTH the case and
 * the canonical finding lifecycle (through the P11 service, §69-style).
 * DUPLICATE points at the canonical primary and preserves history —
 * nothing is deleted. ACCEPT_RISK_CANDIDATE only MARKS candidacy; risk
 * acceptance itself happens through the exception workflow (§78).
 */
@Injectable()
export class TriageService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly state: CaseStateService,
    private readonly vulnerabilities: VulnerabilityService,
  ) {}

  async triage(user: RequestUser, workspaceId: string, caseId: string, input: {
    decision: TriageDecision; reason: string; priority?: string; notes?: string;
    evidence?: unknown; canonicalFindingId?: string; reviewAt?: Date;
  }) {
    requireRemediationPermission(user, "TRIAGE_FINDINGS");
    if (!(TRIAGE_DECISIONS as readonly string[]).includes(input.decision)) {
      throw new BadRequestException(`unknown triage decision ${input.decision}`);
    }
    if (!input.reason?.trim()) throw new BadRequestException("triage requires a reason (§10)");
    const kase = await this.state.getCase(workspaceId, caseId);
    if (input.decision === "FALSE_POSITIVE" && (input.evidence === undefined || input.evidence === null)) {
      throw new BadRequestException("false positive requires evidence (§12)");
    }
    if (input.decision === "DUPLICATE") {
      if (!input.canonicalFindingId) throw new BadRequestException("duplicate triage requires the canonical primary finding (§13)");
      const canonical = await this.state.getFinding(workspaceId, input.canonicalFindingId);
      if (canonical.id === kase.findingId) throw new BadRequestException("a finding cannot be its own canonical primary");
    }
    const record = await this.prisma.remediationTriage.create({
      data: {
        caseId, workspaceId, decision: input.decision, analystId: user.id,
        priority: input.priority ?? null, reason: input.reason, notes: input.notes ?? null,
        evidence: (input.evidence as never) ?? null,
        canonicalFindingId: input.canonicalFindingId ?? null,
        reviewAt: input.reviewAt ?? null,
      },
    });
    let updated = kase;
    if (input.priority && input.priority !== kase.priority) {
      updated = await this.prisma.remediationCase.update({
        where: { id: caseId }, data: { priority: input.priority } as never,
      }) as typeof kase;
    }
    switch (input.decision) {
      case "ACTION_REQUIRED":
        if (kase.status === "NEW" || kase.status === "REOPENED") {
          updated = await this.state.transition(user, workspaceId, updated, { to: "TRIAGED", reason: input.reason });
        }
        break;
      case "FALSE_POSITIVE": {
        updated = await this.state.transition(user, workspaceId, updated, {
          to: "FALSE_POSITIVE", reason: input.reason, evidence: input.evidence,
        });
        // Mirror onto the canonical lifecycle via the P11 service —
        // FALSE_POSITIVE there also demands reason + reviewer (§51).
        const finding = await this.state.getFinding(workspaceId, kase.findingId);
        if (finding.lifecycleStatus !== "FALSE_POSITIVE") {
          try {
            await this.vulnerabilities.transition(user, workspaceId, kase.findingId, {
              to: "FALSE_POSITIVE" as never, reason: input.reason, reviewerId: user.id,
            });
          } catch {
            // The case record stands; the finding walk is retried by the
            // analyst from the VM queue (its machine may require a
            // reclassification step first, §48). Recorded, not hidden:
            await this.prisma.remediationStatusHistory.create({
              data: {
                caseId, workspaceId, fromStatus: updated.status, toStatus: updated.status,
                actorId: user.id, reason: "finding lifecycle mirror deferred — see vulnerability queue",
                evidence: { triageId: record.id } as never,
              },
            });
          }
        }
        break;
      }
      case "DUPLICATE": {
        // The case parks as DEFERRED with the canonical reference — its
        // history is preserved (§13), the canonical case carries the work.
        if (["NEW", "TRIAGED", "ASSIGNED"].includes(updated.status)) {
          updated = await this.state.transition(user, workspaceId, updated, {
            to: "DEFERRED", reason: `duplicate of canonical finding ${input.canonicalFindingId}`,
            evidence: { canonicalFindingId: input.canonicalFindingId },
          });
        }
        break;
      }
      case "NEEDS_MORE_EVIDENCE":
        // Back to NEW for another evidence round — only where the state
        // machine allows it; otherwise the triage record alone stands.
        if (updated.status === "TRIAGED") {
          updated = await this.state.transition(user, workspaceId, updated, { to: "NEW", reason: input.reason });
        }
        break;
      default:
        break;
    }
    await this.state.emit(user, workspaceId, kase, "REMEDIATION_TRIAGED", { decision: input.decision, triageId: record.id });
    return { case: updated, triage: record };
  }
}
