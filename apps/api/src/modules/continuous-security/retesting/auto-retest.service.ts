import { BadRequestException, Inject, Injectable } from "@nestjs/common";
import { evaluateAutoRetestEligibility, type RetestTrigger } from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { AuditService } from "../../audit/audit.service";
import { RetestService } from "../../vulnerabilities/retest.service";
import { requireContinuousPermission } from "../permissions";

/**
 * Automatic retesting (Prompt 22 §51–§56). A retest is requested
 * ONLY when the SDK AutoRetestPolicy evaluator says the finding is
 * eligible — which itself requires the Prompt 20 RetestRouter to
 * route it AND a Prompt 16 governed SAFE validator to support it.
 * Requests go through the existing Prompt 11 RetestService, so the
 * retest executes as an ordinary governed scan, never as an ad-hoc
 * action. Prohibited validation families (§53) are refused here with
 * the reason recorded — they are unschedulable, forever.
 */
@Injectable()
export class AutoRetestService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly retests: RetestService,
  ) {}

  async getPolicy(user: RequestUser, workspaceId: string) {
    requireContinuousPermission(user, "VIEW_CONTINUOUS_SECURITY");
    const row = await this.prisma.autoRetestPolicy.findFirst({ where: { workspaceId } });
    return row ?? { workspaceId, enabled: false, triggers: [], maxPerDay: 50, note: "no auto-retest policy configured — automatic retesting is OFF (fail closed)" };
  }

  async updatePolicy(user: RequestUser, workspaceId: string, input: { enabled: boolean; triggers?: string[]; maxPerDay?: number }) {
    requireContinuousPermission(user, "MANAGE_SCAN_SCHEDULES");
    const triggers = input.triggers ?? [];
    const maxPerDay = input.maxPerDay ?? 50;
    const existing = await this.prisma.autoRetestPolicy.findFirst({ where: { workspaceId } });
    if (existing) {
      return this.prisma.autoRetestPolicy.update({
        where: { id: existing.id },
        data: { enabled: input.enabled, triggers: triggers as never, maxPerDay },
      });
    }
    return this.prisma.autoRetestPolicy.create({
      data: { workspaceId, enabled: input.enabled, triggers: triggers as never, maxPerDay, createdBy: user.id },
    });
  }

  /** Build the SDK evaluation view from a stored finding. */
  private toFindingView(finding: {
    id: string; title: string; vulnClass: string | null; cwe: string | null; cve: string | null;
    host: string | null; port: number | null; endpoint: string | null; sources: string[];
    lifecycleStatus: string; sourceDomain: string | null; assetId: string | null;
    confidence: number; severity: string; category: string | null;
  }) {
    return {
      id: finding.id, title: finding.title, vulnClass: finding.vulnClass ?? finding.category,
      cwe: finding.cwe, cve: finding.cve, host: finding.host, port: finding.port,
      endpoint: finding.endpoint, sources: finding.sources,
      lifecycleStatus: finding.lifecycleStatus, sourceDomain: finding.sourceDomain,
    };
  }

  /**
   * Request a retest for one finding if (and only if) eligible.
   * Used by workflows, by RETEST schedules and by the API. Returns a
   * refusal with the reason instead of throwing for ineligible
   * findings — batch callers record refusals as run outcomes.
   */
  async requestRetestForFinding(
    workspaceId: string,
    findingId: string,
    trigger: RetestTrigger,
    actor?: { userId: string; organizationId: string; role: RequestUser["role"]; email?: string },
  ): Promise<{ requested: boolean; reason: string; retestId?: string }> {
    const finding = await this.prisma.finding.findFirst({ where: { id: findingId, workspaceId } });
    if (!finding) return { requested: false, reason: "finding not found in this workspace" };
    // The workspace AutoRetestPolicy governs EVERY automatic retest,
    // including API-initiated ones: disabled ⇒ fail closed (§51).
    const policy = await this.prisma.autoRetestPolicy.findFirst({ where: { workspaceId } });
    if (!policy?.enabled) {
      return { requested: false, reason: "auto-retest policy is disabled for this workspace (fail closed, §51)" };
    }
    const enabledTriggers = (policy.triggers as string[]) ?? [];
    if (enabledTriggers.length > 0 && !enabledTriggers.includes(trigger)) {
      return { requested: false, reason: `trigger ${trigger} is not enabled by the workspace auto-retest policy (§54)` };
    }
    const evaluation = evaluateAutoRetestEligibility(this.toFindingView(finding), trigger);
    if (!evaluation.eligible) return { requested: false, reason: evaluation.reason };

    const todayStart = new Date(); todayStart.setHours(0, 0, 0, 0);
    // Conservative bound: ALL retest requests created today in the
    // workspace (manual + automatic) count against the auto cap.
    const createdToday = await this.prisma.retestRequest.count({
      where: { workspaceId, createdAt: { gte: todayStart } },
    });
    if (createdToday >= policy.maxPerDay) {
      return { requested: false, reason: `auto-retest daily cap reached (${policy.maxPerDay}) — bounded automation (§51)` };
    }
    const requester: RequestUser = actor
      ? { id: actor.userId, email: actor.email ?? "scheduler@zerosweep", organizationId: actor.organizationId, role: actor.role }
      : { id: "scheduler", email: "scheduler@zerosweep", organizationId: "", role: "SECURITY_ENGINEER" };
    let created: { id: string };
    try {
      created = await this.retests.requestRetest(requester, workspaceId, findingId, `auto-retest (${trigger}): ${evaluation.reason}`);
    } catch (err) {
      // The governed retest path refused (in-flight duplicate,
      // permission, lifecycle) — recorded as a refusal, not a crash.
      return { requested: false, reason: err instanceof Error ? err.message : String(err) };
    }
    if (actor) {
      await this.audit.record({
        actorId: actor.userId, organizationId: actor.organizationId, workspaceId,
        action: "AUTO_RETEST_REQUESTED", resourceType: "Finding", resourceId: findingId,
        metadata: { trigger, validator: evaluation.validatorSlug, retestId: created.id },
      });
    }
    return { requested: true, reason: evaluation.reason, retestId: created.id };
  }

  /** API entry: manual request for one finding (still fully gated). */
  async requestRetest(user: RequestUser, workspaceId: string, findingId: string, trigger: RetestTrigger) {
    requireContinuousPermission(user, "MANAGE_SCAN_SCHEDULES");
    const result = await this.requestRetestForFinding(workspaceId, findingId, trigger, {
      userId: user.id, organizationId: user.organizationId, role: user.role, email: user.email,
    });
    if (!result.requested) throw new BadRequestException(`auto-retest refused: ${result.reason} (§51–§53)`);
    return result;
  }
}
