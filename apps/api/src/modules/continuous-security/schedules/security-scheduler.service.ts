import { createHash } from "node:crypto";
import { lookup } from "node:dns/promises";
import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  classifyProfile, decideLease, decideMissedRuns, decideRetry, evaluateFrequency, evaluateWindows,
  findEquivalentRunningScan, nextCronRun, nextLeaseUntil, revalidateScope, scheduleRunKey,
  type HostResolver,
} from "@dsrclone/security-sdk";
import { scopeRulesSchema } from "@dsrclone/validation";
import type { Role } from "@dsrclone/types";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { AuditService } from "../../audit/audit.service";
import { OrchestrationService } from "../../orchestration/orchestration.service";
import { VmReportsService } from "../../vulnerability-management/vm-reports.service";
import { ValidationWorkflowService } from "../../security-validation/workflows/validation-workflow.service";
import { requireContinuousPermission } from "../permissions";
import { MonitoringPolicyService } from "../monitoring/monitoring-policy.service";
import { AutoRetestService } from "../retesting/auto-retest.service";
import { SnapshotService } from "../snapshots/snapshot.service";
import { DriftService } from "../drift/drift.service";
import { evaluateAutoRetestEligibility } from "@dsrclone/security-sdk";

const LEASE_SCOPE = "continuous-scheduler";
const MAX_INSTANTS_PER_SCHEDULE = 50;
const MAX_POLICY_FANOUT = 25;
const MAX_REVALIDATION_PER_RUN = 10;
const MAX_RETEST_PER_RUN = 25;

const dnsHostResolver: HostResolver = async (host) => {
  const records = await lookup(host, { all: true });
  return records.map((r) => r.address);
};

interface RunOutcome {
  status: string;
  reasonCode?: string;
  reason?: string;
  scanId?: string;
  reportId?: string;
  validationRequestId?: string;
  deferredUntil?: Date;
}

/**
 * The intelligent scheduler (Prompt 22 §7/§8). A tick:
 *   acquire the DB lease (§23/§24) → find due schedules → plan with
 *   backpressure + tenant fairness (§95/§96) → for each due instant
 *   apply missed-run policy (§20) → run EVERY gate (safety class §9,
 *   frequency §13, windows §15/§16, concurrency/dedupe §17/§18,
 *   authorization §25, DNS scope revalidation §26) → materialize
 *   ONLY through the existing governed paths (OrchestrationService
 *   for scans, Prompt 20 reports, Prompt 16 validation requests,
 *   Prompt 11 retests). A schedule NEVER bypasses a gate and NEVER
 *   runs a scanner directly. Gate refusals are persisted runs with
 *   reason codes — never silent, never retried (§21).
 *
 * Tests drive tick() with a fake clock; no timer is required for
 * correctness (a deployment may call tick on an interval).
 */
@Injectable()
export class SecuritySchedulerService {
  /** DNS seam — tests inject a fake resolver; no network in tests. */
  resolver: HostResolver = dnsHostResolver;

  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly policies: MonitoringPolicyService,
    private readonly orchestration: OrchestrationService,
    private readonly reports: VmReportsService,
    private readonly validations: ValidationWorkflowService,
    private readonly autoRetest: AutoRetestService,
    private readonly snapshots: SnapshotService,
    private readonly drift: DriftService,
  ) {}

  // ---------- CRUD ----------

  async createSchedule(user: RequestUser, workspaceId: string, rawInput: {
    name: string; kind?: string; policyId?: string; assessmentId?: string; reportScheduleId?: string;
    frequency?: string; cronExpression?: string; timezone?: string; missedRunPolicy?: string;
    allowConcurrent?: boolean; enabled?: boolean;
  }) {
    requireContinuousPermission(user, "MANAGE_SCAN_SCHEDULES");
    const input = {
      ...rawInput,
      kind: rawInput.kind ?? "SCAN",
      frequency: rawInput.frequency ?? "DAILY",
      timezone: rawInput.timezone ?? "UTC",
      missedRunPolicy: rawInput.missedRunPolicy ?? "RUN_ONCE",
      allowConcurrent: rawInput.allowConcurrent ?? false,
    };
    let profile: string | undefined;
    let policy: Awaited<ReturnType<MonitoringPolicyService["getPolicy"]>> | undefined;
    if (input.policyId) {
      policy = await this.policies.getPolicy(user, workspaceId, input.policyId);
    }
    if (input.kind === "SCAN") {
      if (input.assessmentId) {
        const assessment = await this.prisma.assessment.findFirst({ where: { id: input.assessmentId, workspaceId }, include: { target: true } });
        if (!assessment) throw new BadRequestException("assessmentId must reference an assessment in this workspace");
        profile = assessment.profile as string;
        this.policies.assertSchedulableProfile(profile);
        // §8: creation-time authorization — the target must be
        // verified and the assessment approved NOW, and again at
        // every fire time (§25).
        if (assessment.status !== "APPROVED") throw new BadRequestException("scheduled scans require an APPROVED assessment at creation (§8)");
        if (!assessment.target.verified) throw new BadRequestException("scheduled scans require a VERIFIED target at creation (§8)");
      } else if (policy) {
        profile = policy.scanProfile;
        this.policies.assertSchedulableProfile(profile);
      } else {
        throw new BadRequestException("a SCAN schedule requires an assessmentId or a monitoring policyId");
      }
    }
    if (input.kind === "REPORT") {
      if (!input.reportScheduleId) throw new BadRequestException("a REPORT schedule requires a reportScheduleId (Prompt 20 definition)");
      const def = await this.prisma.reportSchedule.findFirst({ where: { id: input.reportScheduleId, workspaceId } });
      if (!def) throw new BadRequestException("reportScheduleId must reference a report schedule in this workspace");
    }
    if (input.kind === "REVALIDATION" && !input.policyId && !input.assessmentId) {
      throw new BadRequestException("a REVALIDATION schedule requires a policyId or assessmentId");
    }
    const expression = this.policies.assertExpression(input.frequency, input.cronExpression, input.timezone);
    const nextRunAt = nextCronRun(expression, input.timezone, new Date());
    if (!nextRunAt) throw new BadRequestException("expression produces no future run");
    const schedule = await this.prisma.securitySchedule.create({
      data: {
        workspaceId, policyId: input.policyId, name: input.name, kind: input.kind,
        assessmentId: input.assessmentId, reportScheduleId: input.reportScheduleId, profile,
        expression, frequency: input.frequency, timezone: input.timezone, nextRunAt,
        missedRunPolicy: input.missedRunPolicy, allowConcurrent: input.allowConcurrent,
        enabled: input.enabled ?? true, createdBy: user.id,
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "SCHEDULE_CREATED", resourceType: "SecuritySchedule", resourceId: schedule.id,
      metadata: { kind: input.kind, expression },
    });
    return schedule;
  }

  async listSchedules(user: RequestUser, workspaceId: string) {
    requireContinuousPermission(user, "VIEW_CONTINUOUS_SECURITY");
    return this.prisma.securitySchedule.findMany({ where: { workspaceId }, orderBy: { nextRunAt: "asc" }, take: 300 });
  }

  async getSchedule(user: RequestUser, workspaceId: string, id: string) {
    requireContinuousPermission(user, "VIEW_CONTINUOUS_SECURITY");
    const schedule = await this.prisma.securitySchedule.findFirst({ where: { id, workspaceId } });
    if (!schedule) throw new NotFoundException("schedule not found in this workspace");
    return schedule;
  }

  private async getScheduleInternal(workspaceId: string, id: string) {
    const schedule = await this.prisma.securitySchedule.findFirst({ where: { id, workspaceId } });
    if (!schedule) throw new NotFoundException("schedule not found in this workspace");
    return schedule;
  }

  async updateSchedule(user: RequestUser, workspaceId: string, id: string, input: {
    name?: string; frequency?: string; cronExpression?: string; timezone?: string;
    missedRunPolicy?: string; allowConcurrent?: boolean; enabled?: boolean;
  }) {
    requireContinuousPermission(user, "MANAGE_SCAN_SCHEDULES");
    const existing = await this.getScheduleInternal(workspaceId, id);
    const data: Record<string, unknown> = { ...input };
    if (input.frequency || input.cronExpression || input.timezone) {
      const frequency = input.frequency ?? existing.frequency;
      const timezone = input.timezone ?? existing.timezone;
      const expression = this.policies.assertExpression(frequency, input.cronExpression ?? existing.expression, timezone);
      data.expression = expression;
      const next = nextCronRun(expression, timezone, new Date());
      if (!next) throw new BadRequestException("expression produces no future run");
      data.nextRunAt = next;
      delete data.cronExpression;
    }
    const updated = await this.prisma.securitySchedule.update({ where: { id }, data: data as never });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "SCHEDULE_UPDATED", resourceType: "SecuritySchedule", resourceId: id,
    });
    return updated;
  }

  async pauseSchedule(user: RequestUser, workspaceId: string, id: string) {
    requireContinuousPermission(user, "MANAGE_SCAN_SCHEDULES");
    await this.getScheduleInternal(workspaceId, id);
    const updated = await this.prisma.securitySchedule.update({ where: { id }, data: { paused: true } });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "SCHEDULE_PAUSED", resourceType: "SecuritySchedule", resourceId: id,
    });
    return updated;
  }

  async resumeSchedule(user: RequestUser, workspaceId: string, id: string) {
    requireContinuousPermission(user, "MANAGE_SCAN_SCHEDULES");
    const existing = await this.getScheduleInternal(workspaceId, id);
    // Resume re-anchors to the next future instant — a paused
    // schedule does not unleash its whole missed backlog (§20).
    const next = nextCronRun(existing.expression, existing.timezone, new Date()) ?? existing.nextRunAt;
    const updated = await this.prisma.securitySchedule.update({ where: { id }, data: { paused: false, nextRunAt: next } });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "SCHEDULE_RESUMED", resourceType: "SecuritySchedule", resourceId: id,
    });
    return updated;
  }

  async deleteSchedule(user: RequestUser, workspaceId: string, id: string) {
    requireContinuousPermission(user, "MANAGE_SCAN_SCHEDULES");
    await this.getScheduleInternal(workspaceId, id);
    await this.prisma.securitySchedule.delete({ where: { id } });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "SCHEDULE_DELETED", resourceType: "SecuritySchedule", resourceId: id,
    });
    return { deleted: true };
  }

  async listRuns(user: RequestUser, workspaceId: string, filters: { scheduleId?: string; status?: string } = {}) {
    requireContinuousPermission(user, "VIEW_AUTOMATION_EXECUTIONS");
    const where: Record<string, unknown> = { workspaceId };
    if (filters.scheduleId) where.scheduleId = filters.scheduleId;
    if (filters.status) where.status = filters.status;
    return this.prisma.scheduleRun.findMany({ where: where as never, orderBy: { createdAt: "desc" }, take: 300 });
  }

  /** §81: upcoming runs view — next instants computed from the
   *  governed expression in each schedule's own timezone. */
  async upcoming(user: RequestUser, workspaceId: string, perSchedule = 5) {
    requireContinuousPermission(user, "VIEW_CONTINUOUS_SECURITY");
    const schedules = await this.prisma.securitySchedule.findMany({
      where: { workspaceId, enabled: true, paused: false }, orderBy: { nextRunAt: "asc" }, take: 100,
    });
    const now = new Date();
    return schedules.map((s) => {
      const upcomingRuns: string[] = [];
      let cursor: Date | null = s.nextRunAt;
      for (let i = 0; i < perSchedule && cursor; i++) {
        upcomingRuns.push(cursor.toISOString());
        cursor = nextCronRun(s.expression, s.timezone, cursor);
      }
      void now;
      return { scheduleId: s.id, name: s.name, kind: s.kind, timezone: s.timezone, upcomingRuns };
    });
  }

  /** §82: run now — still passes EVERY policy check (no gate skip). */
  async runNow(user: RequestUser, workspaceId: string, id: string) {
    requireContinuousPermission(user, "RUN_SCHEDULE_NOW");
    const schedule = await this.getScheduleInternal(workspaceId, id);
    if (!schedule.enabled) throw new BadRequestException("schedule is disabled");
    if (schedule.paused) throw new BadRequestException("schedule is paused — resume it before running");
    const outcome = await this.executeScheduleRun(schedule, new Date(), { manualActor: user });
    return outcome;
  }

  // ---------- Tick engine ----------

  async tick(now: Date, owner: string) {
    // 1) Lease (§23/§24): one active scheduler platform-wide.
    const existingLease = await this.prisma.schedulerLease.findUnique({ where: { scope: LEASE_SCOPE } });
    const ttl = 120;
    const decision = decideLease({ existing: existingLease, owner, now, ttlSeconds: ttl });
    if (decision.action === "HELD_BY_OTHER") {
      return { acquired: false, heldBy: existingLease?.owner, processed: 0, runs: [] as RunOutcome[] };
    }
    const leaseData = { owner, leaseUntil: nextLeaseUntil(now, ttl), heartbeatAt: now };
    if (existingLease) {
      await this.prisma.schedulerLease.update({ where: { scope: LEASE_SCOPE }, data: leaseData });
    } else {
      await this.prisma.schedulerLease.create({ data: { scope: LEASE_SCOPE, ...leaseData } });
    }

    const summary: { acquired: boolean; processed: number; runs: RunOutcome[]; deferred: number; retried: number } = {
      acquired: true, processed: 0, runs: [], deferred: 0, retried: 0,
    };

    // 2) Due retries first (§21: only retryable classes ever land here).
    const retries = await this.prisma.scheduleRun.findMany({
      where: { status: "FAILED", nextAttemptAt: { lte: now } }, take: 50, orderBy: { nextAttemptAt: "asc" },
    });
    for (const run of retries) {
      const schedule = await this.prisma.securitySchedule.findFirst({ where: { id: run.scheduleId } });
      if (!schedule || !schedule.enabled || schedule.paused) continue;
      const outcome = await this.executeScheduleRun(schedule, run.scheduledFor, { existingRun: run });
      summary.runs.push(outcome);
      summary.retried++;
    }

    // 3) Due schedules with backpressure + fairness planning (§95/§96).
    const due = await this.prisma.securitySchedule.findMany({
      where: { enabled: true, paused: false, nextRunAt: { lte: now } },
      orderBy: { nextRunAt: "asc" }, take: 200,
    });
    if (due.length > 0) {
      const runningScans = await this.prisma.scan.findMany({
        where: { status: { in: ["QUEUED", "RUNNING"] } }, select: { workspaceId: true }, take: 5000,
      });
      const runningByWorkspace: Record<string, number> = {};
      for (const s of runningScans) runningByWorkspace[s.workspaceId] = (runningByWorkspace[s.workspaceId] ?? 0) + 1;
      const queueDepth = runningScans.length;
      const settingsByWorkspace = new Map<string, Awaited<ReturnType<MonitoringPolicyService["getSettings"]>>>();
      for (const s of due) {
        if (!settingsByWorkspace.has(s.workspaceId)) settingsByWorkspace.set(s.workspaceId, await this.policies.getSettings(s.workspaceId));
      }
      const threshold = Math.min(...[...settingsByWorkspace.values()].map((v) => v.queueDepthThreshold));
      const overloaded = queueDepth > threshold;
      const touchedWorkspaces = new Set<string>();
      if (overloaded) {
        summary.deferred = due.length; // §95: defer rather than flood the queue
      } else {
        // Fair interleave: round-robin by workspace (§96).
        const queues = new Map<string, typeof due>();
        for (const s of due) queues.set(s.workspaceId, [...(queues.get(s.workspaceId) ?? []), s]);
        const ordered: typeof due = [];
        let progressed = true;
        while (progressed) {
          progressed = false;
          for (const q of queues.values()) {
            const next = q.shift();
            if (next) { ordered.push(next); progressed = true; }
          }
        }
        for (const schedule of ordered) {
          const settings = settingsByWorkspace.get(schedule.workspaceId)!;
          const running = runningByWorkspace[schedule.workspaceId] ?? 0;
          if (schedule.kind === "SCAN" && running >= settings.maxConcurrentScheduledScans) {
            summary.deferred++;
            continue;
          }
          const outcomes = await this.processDueSchedule(schedule, now);
          summary.runs.push(...outcomes);
          summary.processed++;
          touchedWorkspaces.add(schedule.workspaceId);
          if (schedule.kind === "SCAN") runningByWorkspace[schedule.workspaceId] = running + 1;
        }
      }
      // 4) Snapshot + drift cadence for touched workspaces (§29).
      for (const workspaceId of touchedWorkspaces) {
        const ws = await this.prisma.workspace.findUnique({ where: { id: workspaceId } });
        const actor = { userId: "scheduler", organizationId: ws?.organizationId ?? "" };
        await this.snapshots.captureSnapshots(workspaceId, "SCHEDULED", actor);
        await this.drift.runDrift(workspaceId, actor);
      }
    }

    // 5) Heartbeat (§24) — written on the TICK's clock so lease
    // arithmetic stays consistent for the caller driving time.
    await this.prisma.schedulerLease.update({ where: { scope: LEASE_SCOPE }, data: { heartbeatAt: now, leaseUntil: nextLeaseUntil(now, ttl) } }).catch(() => undefined);
    return summary;
  }

  /** Expand a due schedule into its missed instants and run them. */
  private async processDueSchedule(schedule: {
    id: string; workspaceId: string; expression: string; timezone: string; nextRunAt: Date; missedRunPolicy: string;
    kind: string; name: string; policyId: string | null; assessmentId: string | null; reportScheduleId: string | null;
    profile: string | null; allowConcurrent: boolean; createdBy: string; failureCount: number;
  }, now: Date): Promise<RunOutcome[]> {
    const instants: Date[] = [];
    let cursor: Date | null = schedule.nextRunAt;
    while (cursor && cursor <= now && instants.length < MAX_INSTANTS_PER_SCHEDULE) {
      instants.push(cursor);
      cursor = nextCronRun(schedule.expression, schedule.timezone, cursor);
    }
    if (instants.length === 0) return [];
    const decision = decideMissedRuns(schedule.missedRunPolicy as never, instants);
    const outcomes: RunOutcome[] = [];
    for (const skipped of decision.skippedInstants) {
      const key = scheduleRunKey({ scheduleId: schedule.id, scheduledFor: skipped });
      const existing = await this.prisma.scheduleRun.findUnique({ where: { scheduleRunKey: key } });
      if (!existing) {
        await this.prisma.scheduleRun.create({
          data: {
            workspaceId: schedule.workspaceId, scheduleId: schedule.id, scheduleRunKey: key,
            scheduledFor: skipped, status: "SKIPPED", reasonCode: "MISSED_RUN_SKIPPED",
            reason: `missed-run policy ${schedule.missedRunPolicy} collapsed ${instants.length} due instant(s) (§20)`,
            startedAt: now, completedAt: now,
          },
        });
      }
      outcomes.push({ status: "SKIPPED", reasonCode: "MISSED_RUN_SKIPPED" });
    }
    const instantsToRun = decision.runsToCreate > 0 ? instants.slice(instants.length - decision.runsToCreate) : [];
    let deferredUntil: Date | undefined;
    let lastOutcome: RunOutcome | undefined;
    for (const instant of instantsToRun) {
      lastOutcome = await this.executeScheduleRun(schedule, instant);
      outcomes.push(lastOutcome);
      if (lastOutcome.deferredUntil) deferredUntil = lastOutcome.deferredUntil;
    }
    const nextRunAt = deferredUntil ?? nextCronRun(schedule.expression, schedule.timezone, now) ?? schedule.nextRunAt;
    await this.prisma.securitySchedule.update({
      where: { id: schedule.id },
      data: {
        nextRunAt, lastRunAt: now, lastStatus: lastOutcome?.status,
        failureCount: lastOutcome && (lastOutcome.status === "FAILED" || lastOutcome.status === "BLOCKED")
          ? schedule.failureCount + 1 : 0,
      },
    });
    return outcomes;
  }

  /** The actor a scheduled run acts as: the schedule's creator, with
   *  their CURRENT workspace role — a demoted creator's schedules
   *  lose the permissions with them (§25 posture). */
  private async actorFor(schedule: { workspaceId: string; createdBy: string }): Promise<RequestUser> {
    const [user, workspace] = await Promise.all([
      this.prisma.user.findUnique({ where: { id: schedule.createdBy } }),
      this.prisma.workspace.findUnique({ where: { id: schedule.workspaceId } }),
    ]);
    const membership = user && workspace
      ? await this.prisma.membership.findFirst({ where: { userId: user.id, organizationId: workspace.organizationId } })
      : null;
    return {
      id: schedule.createdBy,
      email: user?.email ?? "scheduler@dsrclone",
      organizationId: workspace?.organizationId ?? "",
      role: ((membership?.role as Role | undefined) ?? "VIEWER"),
    };
  }

  /**
   * Execute (or refuse) ONE scheduled instant. Every gate runs here;
   * the outcome is always a persisted ScheduleRun.
   */
  async executeScheduleRun(
    schedule: {
      id: string; workspaceId: string; kind: string; name: string; policyId: string | null;
      assessmentId: string | null; reportScheduleId: string | null; profile: string | null;
      expression: string; timezone: string; allowConcurrent: boolean; createdBy: string;
    },
    instant: Date,
    options: { manualActor?: RequestUser; existingRun?: { id: string; attempts: number } } = {},
  ): Promise<RunOutcome> {
    const workspaceId = schedule.workspaceId;
    const settings = await this.policies.getSettings(workspaceId);
    const actor = options.manualActor ?? (await this.actorFor(schedule));
    const runKey = scheduleRunKey({ scheduleId: schedule.id, scheduledFor: instant });

    const persist = async (outcome: RunOutcome): Promise<RunOutcome> => {
      const data = {
        workspaceId, scheduleId: schedule.id, scheduleRunKey: runKey, scheduledFor: instant,
        status: outcome.status, reasonCode: outcome.reasonCode, reason: outcome.reason,
        scanId: outcome.scanId, reportId: outcome.reportId, validationRequestId: outcome.validationRequestId,
        attempts: options.existingRun ? options.existingRun.attempts + 1 : 0,
        startedAt: instant, completedAt: new Date(),
      };
      if (options.existingRun) {
        await this.prisma.scheduleRun.update({ where: { id: options.existingRun.id }, data: data as never });
      } else {
        const dupe = await this.prisma.scheduleRun.findUnique({ where: { scheduleRunKey: runKey } });
        if (dupe) return { status: dupe.status, reasonCode: dupe.reasonCode ?? "ALREADY_MATERIALIZED", reason: "this instant was already materialized (§19 idempotency)" };
        await this.prisma.scheduleRun.create({ data: data as never });
      }
      if (outcome.status === "BLOCKED" || outcome.status === "SKIPPED" || outcome.status === "DEFERRED") {
        await this.audit.record({
          actorId: actor.id, organizationId: actor.organizationId, workspaceId,
          action: "SCHEDULE_RUN_BLOCKED", resourceType: "SecuritySchedule", resourceId: schedule.id,
          metadata: { status: outcome.status, reasonCode: outcome.reasonCode, runKey },
        });
      }
      return outcome;
    };

    // Gate 1 — safety class (§9): the stored profile snapshot must
    // still classify SAFE_AUTOMATED at fire time.
    if ((schedule.kind === "SCAN") && schedule.profile) {
      const classification = classifyProfile(schedule.profile);
      if (!classification.schedulable) {
        return persist({ status: "BLOCKED", reasonCode: "PROFILE_NOT_SCHEDULABLE", reason: `profile ${schedule.profile} is ${classification.safetyClass}: ${classification.reason}` });
      }
    }

    // Gate 2 — frequency + budget (§13).
    const dayStart = new Date(instant); dayStart.setHours(0, 0, 0, 0);
    const runsToday = await this.prisma.scheduleRun.count({ where: { workspaceId, createdAt: { gte: dayStart } } });
    if (schedule.kind === "SCAN" && schedule.profile) {
      const frequency = evaluateFrequency({
        profile: schedule.profile, expression: schedule.expression, timezone: schedule.timezone,
        targetCount: 1, runsTodayForWorkspace: runsToday, dailyRunBudget: settings.dailyRunBudget,
      });
      if (!frequency.allowed) {
        return persist({ status: "SKIPPED", reasonCode: frequency.reasonCode, reason: frequency.message });
      }
    } else if (runsToday >= settings.dailyRunBudget) {
      return persist({ status: "SKIPPED", reasonCode: "DAILY_BUDGET_EXHAUSTED", reason: `workspace daily run budget (${settings.dailyRunBudget}) exhausted (§13)` });
    }

    // Gate 3 — maintenance + blackout windows (§15/§16).
    const windows = await this.policies.windowsFor(workspaceId, schedule.policyId);
    const windowVerdict = evaluateWindows(instant, windows.maintenance, windows.blackouts);
    if (!windowVerdict.allowed) {
      if (windowVerdict.reasonCode === "BLACKOUT" && windowVerdict.deferredUntil) {
        return persist({ status: "DEFERRED", reasonCode: "BLACKOUT", reason: windowVerdict.message, deferredUntil: windowVerdict.deferredUntil });
      }
      return persist({ status: "SKIPPED", reasonCode: windowVerdict.reasonCode, reason: windowVerdict.message });
    }

    // Gate 4–6 — kind-specific authorization + materialization.
    try {
      switch (schedule.kind) {
        case "SCAN":
          return persist(await this.materializeScan(schedule, actor, settings));
        case "REPORT":
          return persist(await this.materializeReport(schedule, actor));
        case "REVALIDATION":
          return persist(await this.materializeRevalidation(schedule, actor, instant));
        case "RETEST":
          return persist(await this.materializeRetest(schedule, actor));
        case "INTEL_SYNC":
          // §49 honesty: no intelligence data source is configured
          // in this deployment and no egress fetcher is wired, so
          // the dataset stays NEVER_SYNCED (Prompt 11). The run is
          // recorded — never faked as a successful sync.
          return persist({
            status: "SKIPPED", reasonCode: "INTEL_SOURCE_NOT_CONFIGURED",
            reason: "no intelligence data source is configured — the local dataset remains NEVER_SYNCED (Prompt 11); no network fetch was attempted",
          });
        default:
          return persist({ status: "BLOCKED", reasonCode: "UNKNOWN_KIND", reason: `unknown schedule kind ${schedule.kind}` });
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      const isPolicyRefusal = err instanceof BadRequestException || err instanceof NotFoundException;
      const errorClass: string = isPolicyRefusal ? "POLICY_DENIED" : "TRANSIENT";
      const retry = decideRetry({
        attempts: options.existingRun ? options.existingRun.attempts + 1 : 0,
        maxAttempts: settings.maxRetryAttempts, errorClass, now: new Date(),
      });
      const outcome: RunOutcome = {
        status: isPolicyRefusal ? "BLOCKED" : "FAILED",
        reasonCode: isPolicyRefusal ? "POLICY_DENIED" : retry.retry ? "TRANSIENT_RETRY_SCHEDULED" : "RETRIES_EXHAUSTED",
        reason: message,
      };
      const persisted = await persist(outcome);
      if (!isPolicyRefusal) {
        const run = await this.prisma.scheduleRun.findUnique({ where: { scheduleRunKey: runKey } });
        if (run) {
          if (retry.retry && retry.nextAttemptAt) {
            await this.prisma.scheduleRun.update({ where: { id: run.id }, data: { nextAttemptAt: retry.nextAttemptAt } });
          } else {
            // §22: exhausted retries land in the dead-letter queue.
            await this.prisma.deadLetterJob.create({
              data: {
                jobId: run.id, queue: "scheduled-runs", errorCategory: "SCHEDULE_RUN_EXHAUSTED",
                errorMessage: message.slice(0, 500), attempts: run.attempts + 1,
              },
            });
          }
        }
      }
      return persisted;
    }
  }

  /** SCAN materialization: authorization (§25) + DNS revalidation
   *  (§26) per assessment, then the gated orchestration path (§7). */
  private async materializeScan(
    schedule: { id: string; workspaceId: string; policyId: string | null; assessmentId: string | null; profile: string | null; allowConcurrent: boolean },
    actor: RequestUser,
    settings: { maxConcurrentScheduledScans: number },
  ): Promise<RunOutcome> {
    const workspaceId = schedule.workspaceId;
    let assessmentIds: string[] = [];
    if (schedule.assessmentId) {
      assessmentIds = [schedule.assessmentId];
    } else if (schedule.policyId) {
      const policy = await this.prisma.monitoringPolicy.findFirst({ where: { id: schedule.policyId, workspaceId } });
      if (!policy) return { status: "BLOCKED", reasonCode: "POLICY_NOT_FOUND", reason: "monitoring policy no longer exists" };
      if (!policy.enabled) return { status: "SKIPPED", reasonCode: "POLICY_DISABLED", reason: "monitoring policy is disabled" };
      const resolved = await this.policies.resolveSelector(workspaceId, (policy.targetSelector ?? {}) as never);
      assessmentIds = resolved.filter((r) => r.profile === policy.scanProfile).map((r) => r.assessmentId).slice(0, MAX_POLICY_FANOUT);
      if (assessmentIds.length === 0) {
        return { status: "SKIPPED", reasonCode: "NO_TARGETS_RESOLVED", reason: "the policy selector resolved to no assessments with the policy profile (§5)" };
      }
    }

    // Concurrency + duplicate prevention (§17/§18/§102).
    const runningScanRows = await this.prisma.scan.findMany({
      where: { workspaceId, status: { in: ["QUEUED", "RUNNING"] } },
      select: { id: true, assessmentId: true, status: true, plan: { select: { profile: true } } }, take: 500,
    });
    const runningScans = runningScanRows.map((s) => ({
      id: s.id, assessmentId: s.assessmentId, status: s.status as string,
      profile: (s.plan?.profile as string | undefined) ?? "",
    }));
    if (runningScans.length >= settings.maxConcurrentScheduledScans) {
      return { status: "DEFERRED", reasonCode: "CONCURRENCY_LIMIT", reason: `workspace already has ${runningScans.length} active scan(s) — scheduled concurrency cap ${settings.maxConcurrentScheduledScans} (§17)`, deferredUntil: new Date(Date.now() + 5 * 60_000) };
    }

    const outcomes: RunOutcome[] = [];
    for (const assessmentId of assessmentIds) {
      outcomes.push(await this.materializeOneScan(schedule, assessmentId, actor, runningScans));
    }
    const ok = outcomes.find((o) => o.status === "ENQUEUED");
    if (ok) return { ...ok, reason: outcomes.length > 1 ? `fan-out: ${outcomes.filter((o) => o.status === "ENQUEUED").length}/${outcomes.length} assessment(s) enqueued` : ok.reason };
    return outcomes[0] ?? { status: "SKIPPED", reasonCode: "NO_TARGETS_RESOLVED", reason: "no assessments resolved" };
  }

  private async materializeOneScan(
    schedule: { id: string; workspaceId: string; allowConcurrent: boolean },
    assessmentId: string,
    actor: RequestUser,
    runningScans: Array<{ id: string; assessmentId: string; profile: string; status: string }>,
  ): Promise<RunOutcome> {
    const assessment = await this.prisma.assessment.findFirst({
      where: { id: assessmentId, workspaceId: schedule.workspaceId },
      include: { target: true, scope: true },
    });
    if (!assessment) return { status: "BLOCKED", reasonCode: "ASSESSMENT_NOT_FOUND", reason: "assessment no longer exists in this workspace" };
    // §25/§99: authorization is rechecked at fire time — an
    // assessment that lost approval (or whose target lost
    // verification) blocks the run. Schedules never resurrect
    // expired approvals.
    if (assessment.status !== "APPROVED") {
      return { status: "BLOCKED", reasonCode: "AUTHORIZATION_EXPIRED", reason: `assessment is ${assessment.status}, not APPROVED — authorization is rechecked before every run (§25)` };
    }
    if (!assessment.target.verified) {
      return { status: "BLOCKED", reasonCode: "TARGET_NOT_VERIFIED", reason: "target is no longer VERIFIED (§25)" };
    }
    if (!schedule.allowConcurrent) {
      const dupe = findEquivalentRunningScan(
        runningScans.map((s) => ({ scanId: s.id, assessmentId: s.assessmentId, profile: s.profile as string, status: s.status })),
        { assessmentId, profile: assessment.profile as string },
      );
      if (dupe) return { status: "SKIPPED", reasonCode: "DUPLICATE_RUN", reason: `an equivalent scan (${dupe.scanId}) is already active for this assessment + profile (§18)` };
    }
    // §26/§100: fresh DNS scope revalidation for network destinations.
    const targetValue = assessment.target.value ?? "";
    const isUrl = /^https?:\/\//i.test(targetValue);
    const looksLikeHost = /^[a-zA-Z0-9.-]+$/.test(targetValue) || /^\d+\.\d+\.\d+\.\d+$/.test(targetValue);
    if (isUrl || looksLikeHost) {
      const scopeRules = scopeRulesSchema.parse((assessment.scope?.rules ?? {}) as never);
      const revalidation = await revalidateScope({
        ...(isUrl ? { url: targetValue } : { host: targetValue }),
        scopeRules, resolver: this.resolver,
        internalEngagementApproved: (assessment.scope as unknown as { internalNetworkApproved?: boolean } | null)?.internalNetworkApproved ?? false,
      });
      if (!revalidation.ok) {
        return { status: "BLOCKED", reasonCode: revalidation.reasonCode, reason: `${revalidation.message} — DNS/scope revalidation at fire time (§26)` };
      }
    }
    // §7: enqueue ONLY through the governed orchestration path,
    // which re-runs every gate itself (defense in depth).
    const started = await this.orchestration.startScan(actor, assessmentId);
    await this.audit.record({
      actorId: actor.id, organizationId: actor.organizationId, workspaceId: schedule.workspaceId,
      action: "SCHEDULE_RUN_STARTED", resourceType: "SecuritySchedule", resourceId: schedule.id,
      metadata: { assessmentId, scanId: started.scanId },
    });
    return { status: "ENQUEUED", scanId: started.scanId, reason: `scan ${started.scanId} enqueued through the gated orchestration path` };
  }

  /** REPORT materialization: execute the Prompt 20 definition. */
  private async materializeReport(
    schedule: { workspaceId: string; reportScheduleId: string | null },
    actor: RequestUser,
  ): Promise<RunOutcome> {
    if (!schedule.reportScheduleId) return { status: "BLOCKED", reasonCode: "REPORT_DEFINITION_MISSING", reason: "schedule has no report definition" };
    const def = await this.prisma.reportSchedule.findFirst({ where: { id: schedule.reportScheduleId, workspaceId: schedule.workspaceId } });
    if (!def) return { status: "BLOCKED", reasonCode: "REPORT_DEFINITION_MISSING", reason: "report definition no longer exists" };
    if (!def.enabled) return { status: "SKIPPED", reasonCode: "REPORT_DEFINITION_DISABLED", reason: "report definition is disabled (Prompt 20)" };
    const report = await this.reports.createReport(actor, schedule.workspaceId, {
      title: `${def.name} — scheduled ${new Date().toISOString().slice(0, 10)}`,
      type: def.reportType, ...(def.templateId ? { templateId: def.templateId } : {}),
    });
    const generated = await this.reports.generate(actor, schedule.workspaceId, report.id, (def.formats as string[]) ?? undefined);
    return { status: "COMPLETED", reportId: report.id, reason: `report ${report.id} generated from definition ${def.id} (${(generated as { snapshotId?: string }).snapshotId ? "snapshot sealed" : "generated"})` };
  }

  /** REVALIDATION materialization (§67): creates Prompt 16
   *  validation REQUESTS for eligible findings. Requests still need
   *  their own approval — the scheduler never approves or executes
   *  validation itself. */
  private async materializeRevalidation(
    schedule: { workspaceId: string; assessmentId: string | null },
    actor: RequestUser,
    instant: Date,
  ): Promise<RunOutcome> {
    const where: Record<string, unknown> = { workspaceId: schedule.workspaceId, duplicateOfId: null };
    if (schedule.assessmentId) {
      const scans = await this.prisma.scan.findMany({ where: { assessmentId: schedule.assessmentId }, select: { id: true }, take: 200 });
      where.scanId = { in: scans.map((s) => s.id) };
    }
    const findings = await this.prisma.finding.findMany({
      where: where as never, take: 100, orderBy: { riskScore: "desc" },
    });
    let created = 0;
    let firstId: string | undefined;
    for (const finding of findings) {
      if (created >= MAX_REVALIDATION_PER_RUN) break;
      const eligibility = evaluateAutoRetestEligibility({
        id: finding.id, title: finding.title, vulnClass: finding.vulnClass ?? finding.category,
        cwe: finding.cwe, cve: finding.cve, host: finding.host, port: finding.port, endpoint: finding.endpoint,
        sources: finding.sources, lifecycleStatus: finding.lifecycleStatus, sourceDomain: finding.sourceDomain,
      }, "SCHEDULED");
      if (!eligibility.eligible || !eligibility.validatorSlug) continue;
      const request = await this.validations.createValidation(actor, schedule.workspaceId, {
        findingId: finding.id, validatorSlug: eligibility.validatorSlug,
        reason: "scheduled revalidation (Prompt 22 §67) — approval still required before any execution",
        idempotencyKey: `sched-revalidation:${scheduleKeyPart(finding.id)}:${eligibility.validatorSlug}:${instant.toISOString().slice(0, 10)}`,
      });
      created++;
      firstId = firstId ?? (request as { id: string }).id;
    }
    if (created === 0) {
      return { status: "SKIPPED", reasonCode: "NO_ELIGIBLE_FINDINGS", reason: "no finding is eligible for a governed SAFE revalidation (§51/§67)" };
    }
    return {
      status: "PENDING_APPROVAL", validationRequestId: firstId,
      reason: `${created} validation request(s) created — each still requires its own Prompt 16 approval; nothing was auto-approved or executed`,
    };
  }

  /** RETEST materialization: governed auto-retest via RetestRouter. */
  private async materializeRetest(
    schedule: { workspaceId: string },
    actor: RequestUser,
  ): Promise<RunOutcome> {
    const findings = await this.prisma.finding.findMany({
      where: { workspaceId: schedule.workspaceId, duplicateOfId: null, lifecycleStatus: { in: ["REMEDIATED", "RETEST_PENDING"] } } as never,
      take: MAX_RETEST_PER_RUN, orderBy: { riskScore: "desc" },
    });
    let requested = 0;
    const refusals: string[] = [];
    for (const finding of findings) {
      const result = await this.autoRetest.requestRetestForFinding(schedule.workspaceId, finding.id, "SCHEDULED", {
        userId: actor.id, organizationId: actor.organizationId, role: actor.role, email: actor.email,
      });
      if (result.requested) requested++;
      else refusals.push(result.reason);
    }
    if (requested === 0) {
      return { status: "SKIPPED", reasonCode: "NO_ELIGIBLE_RETESTS", reason: refusals[0] ?? "no remediated findings awaiting retest" };
    }
    return { status: "COMPLETED", reason: `${requested} governed retest(s) requested through the RetestRouter + SAFE catalog path` };
  }
}

function scheduleKeyPart(value: string): string {
  return createHash("sha256").update(value).digest("hex").slice(0, 16);
}
