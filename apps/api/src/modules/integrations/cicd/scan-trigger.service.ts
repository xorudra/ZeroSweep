import { Inject, Injectable } from "@nestjs/common";
import { revalidateScope, type HostResolver } from "@zerosweep/security-sdk";
import { scopeRulesSchema } from "@zerosweep/validation";
import type { Role } from "@zerosweep/types";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import { OrchestrationService } from "../../orchestration/orchestration.service";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { dnsResolver } from "../../continuous-security/notifications/notification-router.service";

type Row = Record<string, unknown>;

export interface TriggerOutcome {
  started: boolean;
  scanId?: string;
  reasonCode?: string;
  detail: string;
}

/**
 * The ONE governed path by which an integration event (webhook,
 * pipeline request) may start a scan (Prompt 24 §17, §31, §32,
 * §116, §136). It mirrors the Prompt 22 scheduler's fire-time
 * discipline exactly:
 *
 * 1. The repository must be linked to a target, and the target must
 *    be VERIFIED at trigger time.
 * 2. An APPROVED assessment must ALREADY EXIST for that target. A
 *    webhook can never create, approve or extend an assessment —
 *    if none exists the trigger is BLOCKED and recorded.
 * 3. Scope is re-validated at trigger time with FRESH DNS; drift to
 *    a protected/private address blocks the run.
 * 4. No duplicate run for the same assessment while one is active.
 * 5. The scan starts as the integration's creator (a real member),
 *    through OrchestrationService — the worker gates re-run anyway.
 */
@Injectable()
export class ScanTriggerService {
  /** DNS seam — tests inject a fake resolver; no network in tests. */
  resolver: HostResolver = dnsResolver;

  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly orchestration: OrchestrationService,
  ) {}

  async actorFor(workspaceId: string, userId: string): Promise<RequestUser> {
    const [user, workspace] = await Promise.all([
      this.prisma.user.findUnique({ where: { id: userId } }),
      this.prisma.workspace.findUnique({ where: { id: workspaceId } }),
    ]);
    const membership = user && workspace
      ? await this.prisma.membership.findFirst({ where: { userId: user.id, organizationId: workspace.organizationId } })
      : null;
    return {
      id: userId,
      email: user?.email ?? "integration@zerosweep",
      organizationId: workspace?.organizationId ?? "",
      role: ((membership?.role as Role | undefined) ?? "VIEWER"),
    };
  }

  async triggerRepositoryScan(input: {
    workspaceId: string;
    repository: Row;
    actorUserId: string;
    purpose: string; // audit context, e.g. "github.push" / "pipeline"
  }): Promise<TriggerOutcome> {
    const repository = input.repository;
    const targetId = repository.targetId as string | null;
    if (!targetId) {
      return { started: false, reasonCode: "TARGET_NOT_LINKED", detail: "repository is not linked to a target — no scan can start" };
    }
    const target = await this.prisma.target.findFirst({ where: { id: targetId, workspaceId: input.workspaceId } });
    if (!target) return { started: false, reasonCode: "TARGET_NOT_FOUND", detail: "linked target not found in this workspace" };
    if (!target.verified) {
      return { started: false, reasonCode: "TARGET_NOT_VERIFIED", detail: "target is not VERIFIED — integration triggers never verify targets (§136)" };
    }
    const assessments = await this.prisma.assessment.findMany({
      where: { workspaceId: input.workspaceId, targetId, status: "APPROVED" },
      orderBy: { createdAt: "desc" },
    });
    const assessment = assessments[0] as Row | undefined;
    if (!assessment) {
      return {
        started: false, reasonCode: "NO_APPROVED_ASSESSMENT",
        detail: "no APPROVED assessment exists for this target — a webhook/pipeline can never approve one (§17/§136); the trigger is blocked, not queued",
      };
    }
    const running = await this.prisma.scan.findFirst({
      where: { assessmentId: assessment.id as string, status: { in: ["QUEUED", "RUNNING", "PAUSED"] } },
    });
    if (running) {
      return { started: true, scanId: running.id as string, detail: "an active scan already exists for the approved assessment — trigger deduplicated" };
    }
    // Fresh-DNS scope revalidation at trigger time (the Prompt 22
    // §26/§100 fire-time discipline): a target that drifted to a
    // protected/private address since approval is refused.
    const targetValue = (target.value as string) ?? "";
    const isUrl = /^https?:\/\//i.test(targetValue);
    const looksLikeHost = /^[a-zA-Z0-9.-]+$/.test(targetValue) || /^\d+\.\d+\.\d+\.\d+$/.test(targetValue);
    if (isUrl || looksLikeHost) {
      const scope = assessment.scopeId
        ? await this.prisma.scope.findUnique({ where: { id: assessment.scopeId as string } })
        : null;
      const scopeRules = scopeRulesSchema.parse(((scope?.rules ?? {}) as never));
      const revalidation = await revalidateScope({
        ...(isUrl ? { url: targetValue } : { host: targetValue }),
        scopeRules,
        resolver: this.resolver,
        internalEngagementApproved: ((scope as unknown as { internalNetworkApproved?: boolean } | null)?.internalNetworkApproved) ?? false,
      });
      if (!revalidation.ok) {
        return { started: false, reasonCode: revalidation.reasonCode, detail: `${revalidation.message} — DNS/scope revalidation at trigger time` };
      }
    }
    const actor = await this.actorFor(input.workspaceId, input.actorUserId);
    const started = await this.orchestration.startScan(actor, assessment.id as string);
    await this.audit.record({
      actorId: input.actorUserId, organizationId: actor.organizationId, workspaceId: input.workspaceId,
      action: "PR_SECURITY_SCAN_STARTED", resourceType: "Scan", resourceId: started.scanId,
      metadata: { purpose: input.purpose, repositoryId: repository.id, assessmentId: assessment.id },
    }).catch(() => undefined);
    return { started: true, scanId: started.scanId, detail: "scan started through the governed orchestration path" };
  }
}
