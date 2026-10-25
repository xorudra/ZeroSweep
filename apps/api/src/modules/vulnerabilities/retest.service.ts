import { BadRequestException, Inject, Injectable } from "@nestjs/common";
import { planRetest, type VmLifecycleStatus } from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { AuditService } from "../audit/audit.service";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { VulnerabilityService } from "./vulnerability.service";
import { QueueService } from "../../queue/queue.service";
import { requireVmPermission } from "./permissions";

/**
 * Retest requests (Prompt 11 §55–§58). The API records a TARGETED
 * retest plan derived from the original detection; execution happens in
 * the worker, which re-runs the original tool/check against the same
 * asset through the SAME authorization/scope/policy/budget gates as the
 * original scan (§57). Outcomes land back on the finding: RESOLVED or
 * REOPENED, with the full history preserved (§58).
 */
@Injectable()
export class RetestService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly vulnerabilities: VulnerabilityService,
    private readonly queue: QueueService,
  ) {}

  async requestRetest(user: RequestUser, workspaceId: string, findingId: string, reason?: string) {
    requireVmPermission(user, "REQUEST_RETEST");
    const finding = await this.vulnerabilities.getFinding(workspaceId, findingId);
    // Evidence metadata carries the original check reference (§56).
    const evidence = await this.prisma.findingEvidence.findFirst({
      where: { findingId }, orderBy: { createdAt: "asc" },
    });
    const checkReference = (evidence?.metadata as { checkId?: string } | null)?.checkId;
    const plan = planRetest({
      fingerprint: finding.fingerprint, host: finding.host, port: finding.port, endpoint: finding.endpoint,
      cve: finding.cve, cwe: finding.cwe, sources: finding.sources,
      ...(checkReference ? { checkReference } : {}),
      lifecycleStatus: finding.lifecycleStatus,
    });
    if (!plan.ok) throw new BadRequestException(plan.error);
    const pending = await this.prisma.retestRequest.findFirst({
      where: { findingId, status: { in: ["QUEUED", "RUNNING"] } },
    });
    if (pending) throw new BadRequestException("a retest is already in flight for this finding");
    const retest = await this.prisma.retestRequest.create({
      data: {
        findingId, workspaceId, requestedBy: user.id,
        sourceTool: plan.plan.sourceTool, checkReference: plan.plan.checkReference,
        // §58: previous evidence reference + the plan are preserved.
        previousEvidence: {
          canonicalFingerprint: plan.plan.canonicalFingerprint,
          lifecycleBefore: finding.lifecycleStatus, reason: reason ?? null,
          rationale: plan.plan.rationale,
        } as never,
      },
    });
    if ((finding.lifecycleStatus as VmLifecycleStatus) === "REMEDIATED") {
      await this.vulnerabilities.transition(user, workspaceId, findingId, { to: "RETEST_PENDING" });
    }
    await this.prisma.findingHistory.create({
      data: { findingId, workspaceId, actorId: user.id, event: "RETEST_REQUESTED", notes: reason, metadata: { retestId: retest.id, sourceTool: plan.plan.sourceTool } as never },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "RETEST_REQUESTED", resourceType: "VULNERABILITY", resourceId: findingId,
      metadata: { retestId: retest.id, sourceTool: plan.plan.sourceTool },
    });
    // Dispatch to the worker (§57): the request row stays QUEUED in
    // Postgres regardless — enqueue failure never loses the request.
    const enqueued = await this.queue.enqueueRetest({ retestId: retest.id, workspaceId });
    return { ...retest, enqueued };
  }

  async listForFinding(workspaceId: string, findingId: string) {
    await this.vulnerabilities.getFinding(workspaceId, findingId);
    return this.prisma.retestRequest.findMany({ where: { findingId }, orderBy: { createdAt: "desc" } });
  }
}
