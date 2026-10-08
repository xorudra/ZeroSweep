import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  classifyProfile, expressionForFrequency, isValidTimezone, validateBlackoutWindow,
  validateCronExpression, validateMaintenanceWindow,
  DEFAULT_SCHEDULER_SETTINGS, type MonitoringTargetSelector, type SchedulerSettingsView,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { AuditService } from "../../audit/audit.service";
import { requireContinuousPermission } from "../permissions";

/**
 * Monitoring policies, maintenance/blackout windows and scheduler
 * settings (Prompt 22 §3–§5, §13–§17).
 *
 * A policy can only ever name a SAFE_AUTOMATED profile (§9): creation
 * with an approval-gated, manual-only or prohibited profile is
 * refused here, and the scheduler refuses again at fire time. The
 * target selector resolves INSIDE the workspace only — discovered
 * third-party assets are never auto-monitored (§4), and resolution
 * never grants authorization (§5/§35).
 */
@Injectable()
export class MonitoringPolicyService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  private auditFor(user: RequestUser, workspaceId: string, action: string, resourceType: string, resourceId: string, metadata?: Record<string, unknown>) {
    return this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: action as never, resourceType, resourceId, ...(metadata ? { metadata } : {}),
    });
  }

  /** Shared profile/expression validation for policies + schedules. */
  assertSchedulableProfile(profile: string): void {
    const classification = classifyProfile(profile);
    if (!classification.schedulable) {
      throw new BadRequestException(
        `profile ${profile} is ${classification.safetyClass} and can never become unattended automation: ${classification.reason} (§9/§122)`,
      );
    }
  }

  assertExpression(frequency: string, cronExpression: string | undefined, timezone: string): string {
    if (!isValidTimezone(timezone)) throw new BadRequestException(`unknown timezone "${timezone}" (§14)`);
    const expression = expressionForFrequency(frequency as never, cronExpression);
    const errors = validateCronExpression(expression);
    if (errors.length > 0) throw new BadRequestException(`invalid schedule expression: ${errors.join("; ")}`);
    return expression;
  }

  async createPolicy(user: RequestUser, workspaceId: string, input: {
    name: string; enabled?: boolean; targetSelector?: MonitoringTargetSelector; scanProfile: string;
    frequency?: string; cronExpression?: string; timezone?: string; safeOnly?: boolean;
    riskThreshold?: number; retestPolicy?: Record<string, unknown>; notificationPolicy?: Record<string, unknown>;
  }) {
    requireContinuousPermission(user, "MANAGE_MONITORING_POLICIES");
    this.assertSchedulableProfile(input.scanProfile);
    if (input.safeOnly === false) {
      throw new BadRequestException("monitoring policies are safe-only by construction — safeOnly cannot be disabled (§9)");
    }
    const frequency = input.frequency ?? "DAILY";
    const timezone = input.timezone ?? "UTC";
    const expression = this.assertExpression(frequency, input.cronExpression, timezone);
    const policy = await this.prisma.monitoringPolicy.create({
      data: {
        workspaceId, name: input.name, enabled: input.enabled ?? true,
        targetSelector: (input.targetSelector ?? {}) as never, scanProfile: input.scanProfile,
        frequency, cronExpression: expression, timezone,
        safeOnly: true, riskThreshold: input.riskThreshold,
        retestPolicy: (input.retestPolicy ?? {}) as never, notificationPolicy: (input.notificationPolicy ?? {}) as never,
        createdBy: user.id,
      },
    });
    await this.auditFor(user, workspaceId, "MONITORING_POLICY_CREATED", "MonitoringPolicy", policy.id, { profile: input.scanProfile });
    return policy;
  }

  async listPolicies(user: RequestUser, workspaceId: string) {
    requireContinuousPermission(user, "VIEW_CONTINUOUS_SECURITY");
    return this.prisma.monitoringPolicy.findMany({ where: { workspaceId }, orderBy: { createdAt: "desc" }, take: 200 });
  }

  async getPolicy(user: RequestUser, workspaceId: string, id: string) {
    requireContinuousPermission(user, "VIEW_CONTINUOUS_SECURITY");
    const policy = await this.prisma.monitoringPolicy.findFirst({ where: { id, workspaceId } });
    if (!policy) throw new NotFoundException("monitoring policy not found in this workspace");
    return policy;
  }

  async updatePolicy(user: RequestUser, workspaceId: string, id: string, input: Record<string, unknown>) {
    requireContinuousPermission(user, "MANAGE_MONITORING_POLICIES");
    const existing = await this.getPolicy(user, workspaceId, id);
    const data: Record<string, unknown> = { ...input };
    const profile = (input.scanProfile as string | undefined) ?? existing.scanProfile;
    this.assertSchedulableProfile(profile);
    if (input.safeOnly === false) throw new BadRequestException("monitoring policies are safe-only by construction (§9)");
    const frequency = (input.frequency as string | undefined) ?? existing.frequency;
    const timezone = (input.timezone as string | undefined) ?? existing.timezone;
    if (input.frequency || input.cronExpression || input.timezone) {
      data.cronExpression = this.assertExpression(frequency, (input.cronExpression as string | undefined) ?? existing.cronExpression ?? undefined, timezone);
    }
    delete data.safeOnly;
    const updated = await this.prisma.monitoringPolicy.update({ where: { id }, data: data as never });
    await this.auditFor(user, workspaceId, "MONITORING_POLICY_UPDATED", "MonitoringPolicy", id);
    return updated;
  }

  async deletePolicy(user: RequestUser, workspaceId: string, id: string) {
    requireContinuousPermission(user, "MANAGE_MONITORING_POLICIES");
    await this.getPolicy(user, workspaceId, id);
    await this.prisma.monitoringPolicy.delete({ where: { id } });
    await this.auditFor(user, workspaceId, "MONITORING_POLICY_DELETED", "MonitoringPolicy", id);
    return { deleted: true };
  }

  /**
   * §5: resolve a policy's selector to concrete assessments inside
   * this workspace. Resolution is a FILTER, not an authorization —
   * every returned assessment is re-authorized at fire time (§25).
   * Bounded (§93/§94): at most 500 assessments per resolution.
   */
  async resolveSelector(workspaceId: string, selector: MonitoringTargetSelector): Promise<Array<{ assessmentId: string; targetId: string; profile: string }>> {
    const sel = selector ?? {};
    if (sel.assessmentIds?.length) {
      const rows = await this.prisma.assessment.findMany({
        where: { id: { in: sel.assessmentIds.slice(0, 500) }, workspaceId },
        select: { id: true, targetId: true, profile: true },
      });
      return rows.map((r) => ({ assessmentId: r.id, targetId: r.targetId, profile: r.profile as string }));
    }
    const assetWhere: Record<string, unknown> = { workspaceId };
    if (sel.assetIds?.length) assetWhere.id = { in: sel.assetIds.slice(0, 500) };
    if (sel.targetIds?.length) assetWhere.targetId = { in: sel.targetIds.slice(0, 500) };
    if (sel.assetTypes?.length) assetWhere.type = { in: sel.assetTypes };
    if (sel.criticalities?.length) assetWhere.criticality = { in: sel.criticalities };
    // Note: tags live on findings, not assets — a tag-only selector
    // resolves via explicit ids; it never widens the asset set.
    const assets = await this.prisma.asset.findMany({ where: assetWhere as never, select: { targetId: true }, take: 500 });
    const targetIds = [...new Set(assets.map((a) => a.targetId))];
    const withExplicitTargets = [...new Set([...targetIds, ...(sel.targetIds ?? [])])];
    if (withExplicitTargets.length === 0) return [];
    const rows = await this.prisma.assessment.findMany({
      where: { targetId: { in: withExplicitTargets }, workspaceId },
      select: { id: true, targetId: true, profile: true },
      take: 500,
    });
    return rows.map((r) => ({ assessmentId: r.id, targetId: r.targetId, profile: r.profile as string }));
  }

  // ---- Maintenance / blackout windows (§15/§16) ----

  async createMaintenanceWindow(user: RequestUser, workspaceId: string, input: {
    name: string; policyId?: string; daysOfWeek?: number[]; startTime: string; endTime: string; timezone?: string; mode?: string;
  }) {
    requireContinuousPermission(user, "MANAGE_MONITORING_POLICIES");
    const normalized = {
      name: input.name, policyId: input.policyId, daysOfWeek: input.daysOfWeek ?? [],
      startTime: input.startTime, endTime: input.endTime,
      timezone: input.timezone ?? "UTC", mode: (input.mode ?? "ALLOWED_HOURS") as "ALLOWED_HOURS" | "BLOCKED_HOURS",
    };
    const errors = validateMaintenanceWindow(normalized);
    if (errors.length > 0) throw new BadRequestException(`invalid maintenance window: ${errors.join("; ")}`);
    return this.prisma.maintenanceWindow.create({
      data: {
        workspaceId, name: normalized.name, policyId: normalized.policyId, daysOfWeek: normalized.daysOfWeek as never,
        startTime: normalized.startTime, endTime: normalized.endTime, timezone: normalized.timezone, mode: normalized.mode, createdBy: user.id,
      },
    });
  }

  async listMaintenanceWindows(user: RequestUser, workspaceId: string) {
    requireContinuousPermission(user, "VIEW_CONTINUOUS_SECURITY");
    return this.prisma.maintenanceWindow.findMany({ where: { workspaceId }, orderBy: { createdAt: "desc" }, take: 200 });
  }

  async createBlackoutWindow(user: RequestUser, workspaceId: string, input: { name: string; reason?: string; startsAt: Date; endsAt: Date }) {
    requireContinuousPermission(user, "MANAGE_MONITORING_POLICIES");
    const errors = validateBlackoutWindow(input);
    if (errors.length > 0) throw new BadRequestException(`invalid blackout window: ${errors.join("; ")}`);
    return this.prisma.blackoutWindow.create({
      data: { workspaceId, name: input.name, reason: input.reason, startsAt: input.startsAt, endsAt: input.endsAt, createdBy: user.id },
    });
  }

  async listBlackoutWindows(user: RequestUser, workspaceId: string) {
    requireContinuousPermission(user, "VIEW_CONTINUOUS_SECURITY");
    return this.prisma.blackoutWindow.findMany({ where: { workspaceId }, orderBy: { startsAt: "desc" }, take: 200 });
  }

  /** Window defs the scheduler evaluates for a workspace (+ policy). */
  async windowsFor(workspaceId: string, policyId?: string | null) {
    const [maintenance, blackouts] = await Promise.all([
      this.prisma.maintenanceWindow.findMany({ where: { workspaceId } }),
      this.prisma.blackoutWindow.findMany({ where: { workspaceId } }),
    ]);
    return {
      maintenance: maintenance
        .filter((w) => !policyId || !w.policyId || w.policyId === policyId)
        .map((w) => ({
          daysOfWeek: (w.daysOfWeek as number[]) ?? [], startTime: w.startTime, endTime: w.endTime,
          timezone: w.timezone, mode: w.mode as "ALLOWED_HOURS" | "BLOCKED_HOURS",
        })),
      blackouts: blackouts.map((b) => ({ startsAt: b.startsAt, endsAt: b.endsAt, ...(b.reason ? { reason: b.reason } : {}) })),
    };
  }

  // ---- Scheduler settings (§13/§17) ----

  async getSettings(workspaceId: string): Promise<SchedulerSettingsView> {
    const row = await this.prisma.schedulerSettings.findFirst({ where: { workspaceId } });
    if (!row) return { ...DEFAULT_SCHEDULER_SETTINGS };
    return {
      maxConcurrentScheduledScans: row.maxConcurrentScheduledScans,
      dailyRunBudget: row.dailyRunBudget,
      queueDepthThreshold: row.queueDepthThreshold,
      leaseTtlSeconds: row.leaseTtlSeconds,
      maxRetryAttempts: row.maxRetryAttempts,
    };
  }

  async updateSettings(user: RequestUser, workspaceId: string, input: Partial<SchedulerSettingsView>) {
    requireContinuousPermission(user, "MANAGE_SCAN_SCHEDULES");
    const existing = await this.prisma.schedulerSettings.findFirst({ where: { workspaceId } });
    if (existing) {
      return this.prisma.schedulerSettings.update({ where: { id: existing.id }, data: { ...input, updatedBy: user.id } as never });
    }
    return this.prisma.schedulerSettings.create({
      data: { workspaceId, ...DEFAULT_SCHEDULER_SETTINGS, ...input, updatedBy: user.id } as never,
    });
  }
}
