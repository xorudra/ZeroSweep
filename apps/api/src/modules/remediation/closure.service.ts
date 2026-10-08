import { BadRequestException, Inject, Injectable } from "@nestjs/common";
import { createHash } from "node:crypto";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { CaseStateService } from "./case-state.service";
import { RemediationSlaService } from "./sla.service";
import { requireRemediationPermission } from "./permissions";

/**
 * Closure engine (Prompt 31 §68–§70). Closure is a CHECKED act, not a
 * status write: verification must be satisfied (or an approved
 * exception active), the closure snapshot preserves the verification,
 * risk, ticket and exception state at closure time, and the canonical
 * finding lifecycle is updated through the state the verification
 * engine already walked (§69) — the snapshot records the finding's
 * actual lifecycle so any divergence is visible, never hidden.
 */
@Injectable()
export class RemediationClosureService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly state: CaseStateService,
    private readonly sla: RemediationSlaService,
  ) {}

  async closeCase(user: RequestUser, workspaceId: string, caseId: string, input: { reason: string }) {
    requireRemediationPermission(user, "CLOSE_VERIFIED_FINDING");
    if (!input.reason?.trim()) throw new BadRequestException("closure requires a reason (§70)");
    const kase = await this.state.getCase(workspaceId, caseId);
    if (!["VERIFIED_FIXED", "ACCEPTED_RISK", "FALSE_POSITIVE", "DEFERRED"].includes(kase.status)) {
      throw new BadRequestException(
        `case is ${kase.status} — closure requires VERIFIED_FIXED (via the verification engine) or an approved exception state (§68)`,
      );
    }
    const finding = await this.state.getFinding(workspaceId, kase.findingId);
    const snapshot = await this.sla.snapshotFor(caseId);
    const jobs = await this.prisma.remediationVerificationJob.findMany({
      where: { caseId }, orderBy: { createdAt: "desc" }, take: 5,
    });
    const workItems = await this.prisma.remediationWorkItem.findMany({ where: { caseId }, take: 10 });
    const exceptions = await this.prisma.remediationException.findMany({
      where: { caseId, status: "APPROVED" }, take: 5,
    });
    const closureSnapshot = {
      reason: input.reason,
      verificationMethod: (jobs[0] as { method?: string } | undefined)?.method ?? null,
      verificationState: kase.verificationState,
      lastVerificationJob: jobs[0] ? { id: jobs[0].id, status: jobs[0].status, method: jobs[0].method } : null,
      riskState: { riskScore: finding.riskScore, riskBand: finding.riskBand, severity: finding.severity, kevListed: finding.kevListed },
      findingLifecycle: finding.lifecycleStatus,
      ticketState: workItems.map((w) => ({ id: w.id, provider: w.provider, status: w.status, externalId: w.externalId })),
      slaState: snapshot ? { state: snapshot.state, dueAt: snapshot.dueAt, policyVersion: snapshot.policyVersion } : null,
      activeExceptions: exceptions.map((e) => ({ id: e.id, type: e.type, expiresAt: e.expiresAt })),
      closedBy: user.id,
      closedAt: new Date().toISOString(),
    };
    const updated = await this.state.transition(user, workspaceId, kase, {
      to: "CLOSED", viaClosure: true, reason: input.reason,
      evidence: { closureSnapshotHash: createHash("sha256").update(JSON.stringify(closureSnapshot)).digest("hex") },
      extraData: { closureSnapshot: closureSnapshot as never },
    });
    if (snapshot && !snapshot.completedAt) {
      await this.prisma.remediationSlaSnapshot.update({
        where: { id: snapshot.id }, data: { completedAt: new Date(), state: "COMPLETED" },
      });
    }
    return { case: updated, closureSnapshot };
  }
}
