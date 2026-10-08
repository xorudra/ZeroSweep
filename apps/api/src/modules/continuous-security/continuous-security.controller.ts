import { Body, Controller, Delete, Get, Inject, Param, Patch, Post, Put, Query } from "@nestjs/common";
import { z } from "zod";
import { parseOrThrow } from "../../common/parse";
import { resolveWorkspace } from "../../common/tenant";
import { CurrentUser, type RequestUser } from "../../common/decorators/auth.decorators";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import {
  autoRetestPolicySchema, blackoutWindowSchema, createPolicySchema, createScheduleSchema,
  createWorkflowSchema, escalationPolicySchema, maintenanceWindowSchema, notificationPolicySchema,
  schedulerSettingsSchema, updatePolicySchema, updateScheduleSchema, updateWorkflowSchema,
} from "./dto/schemas";
import { MonitoringPolicyService } from "./monitoring/monitoring-policy.service";
import { SecuritySchedulerService } from "./schedules/security-scheduler.service";
import { SnapshotService } from "./snapshots/snapshot.service";
import { DriftService } from "./drift/drift.service";
import { WorkflowService } from "./workflows/workflow.service";
import { NotificationRouterService } from "./notifications/notification-router.service";
import { AutoRetestService } from "./retesting/auto-retest.service";
import { MonitoringAnalyticsService } from "./analytics/monitoring-analytics.service";

const dateSchema = z.object({ date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/) });

/**
 * Continuous-security API (Prompt 22 §86). Every handler resolves
 * the caller's workspace through the tenant helper — a request can
 * only ever touch its own organization's workspace (§120).
 */
@Controller("monitoring")
export class MonitoringController {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly policies: MonitoringPolicyService,
    private readonly analytics: MonitoringAnalyticsService,
    private readonly autoRetest: AutoRetestService,
    private readonly scheduler: SecuritySchedulerService,
  ) {}

  @Post("policies")
  async createPolicy(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.policies.createPolicy(user, ws.id, parseOrThrow(createPolicySchema, body ?? {}));
  }

  @Get("policies")
  async listPolicies(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.policies.listPolicies(user, ws.id);
  }

  @Get("policies/:id")
  async getPolicy(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.policies.getPolicy(user, ws.id, id);
  }

  @Patch("policies/:id")
  async updatePolicy(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.policies.updatePolicy(user, ws.id, id, parseOrThrow(updatePolicySchema, body ?? {}));
  }

  @Delete("policies/:id")
  async deletePolicy(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.policies.deletePolicy(user, ws.id, id);
  }

  @Post("windows")
  async createWindow(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.policies.createMaintenanceWindow(user, ws.id, parseOrThrow(maintenanceWindowSchema, body ?? {}));
  }

  @Get("windows")
  async listWindows(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.policies.listMaintenanceWindows(user, ws.id);
  }

  @Post("blackouts")
  async createBlackout(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.policies.createBlackoutWindow(user, ws.id, parseOrThrow(blackoutWindowSchema, body ?? {}));
  }

  @Get("blackouts")
  async listBlackouts(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.policies.listBlackoutWindows(user, ws.id);
  }

  @Get("scheduler-settings")
  async getSettings(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.policies.getSettings(ws.id);
  }

  @Put("scheduler-settings")
  async updateSettings(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.policies.updateSettings(user, ws.id, parseOrThrow(schedulerSettingsSchema, body ?? {}));
  }

  @Get("health")
  async health(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.analytics.health(user, ws.id);
  }

  @Get("retention")
  async retention(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.analytics.retentionReport(user, ws.id);
  }

  @Post("tick")
  async tick(@CurrentUser() user: RequestUser) {
    await resolveWorkspace(this.prisma, user);
    // Operator-triggered tick (deployments may also run it on a
    // timer). Owner identity is the invoking admin for lease audit.
    return this.scheduler.tick(new Date(), `admin:${user.id}`);
  }

  @Get("auto-retest-policy")
  async getAutoRetestPolicy(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.autoRetest.getPolicy(user, ws.id);
  }

  @Put("auto-retest-policy")
  async updateAutoRetestPolicy(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.autoRetest.updatePolicy(user, ws.id, parseOrThrow(autoRetestPolicySchema, body ?? {}));
  }

  @Post("auto-retest/:findingId")
  async requestAutoRetest(@CurrentUser() user: RequestUser, @Param("findingId") findingId: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.autoRetest.requestRetest(user, ws.id, findingId, "REMEDIATION_MARKER");
  }
}

@Controller("schedules")
export class SchedulesController {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly scheduler: SecuritySchedulerService,
  ) {}

  @Post()
  async create(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.scheduler.createSchedule(user, ws.id, parseOrThrow(createScheduleSchema, body ?? {}));
  }

  @Get()
  async list(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.scheduler.listSchedules(user, ws.id);
  }

  @Get("runs")
  async runs(@CurrentUser() user: RequestUser, @Query("scheduleId") scheduleId?: string, @Query("status") status?: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.scheduler.listRuns(user, ws.id, { scheduleId, status });
  }

  @Get("upcoming")
  async upcoming(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.scheduler.upcoming(user, ws.id);
  }

  @Get(":id")
  async get(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.scheduler.getSchedule(user, ws.id, id);
  }

  @Patch(":id")
  async update(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.scheduler.updateSchedule(user, ws.id, id, parseOrThrow(updateScheduleSchema, body ?? {}));
  }

  @Delete(":id")
  async remove(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.scheduler.deleteSchedule(user, ws.id, id);
  }

  @Post(":id/run")
  async run(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.scheduler.runNow(user, ws.id, id);
  }

  @Post(":id/pause")
  async pause(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.scheduler.pauseSchedule(user, ws.id, id);
  }

  @Post(":id/resume")
  async resume(@CurrentUser() user: RequestUser, @Param("id") id: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.scheduler.resumeSchedule(user, ws.id, id);
  }
}

@Controller("posture")
export class PostureController {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly snapshots: SnapshotService,
    private readonly analytics: MonitoringAnalyticsService,
    private readonly drift: DriftService,
  ) {}

  @Get("snapshots")
  async list(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.snapshots.listPosture(user, ws.id);
  }

  @Post("snapshots")
  async capture(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.snapshots.captureSnapshots(ws.id, "MANUAL", { userId: user.id, organizationId: user.organizationId });
  }

  @Get("rollups")
  async rollups(@CurrentUser() user: RequestUser, @Query("granularity") granularity?: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    const g = granularity === "HOURLY" || granularity === "WEEKLY" ? granularity : "DAILY";
    return this.analytics.postureRollups(user, ws.id, g);
  }

  @Get("daily-summary")
  async summaries(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.analytics.listDailySummaries(user, ws.id);
  }

  @Post("daily-summary")
  async generateSummary(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    const { date } = parseOrThrow(dateSchema, body ?? {});
    return this.analytics.generateDailySummary(user, ws.id, date);
  }

  @Get("timeline")
  async timeline(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.drift.timeline(user, ws.id);
  }
}

@Controller("drift")
export class DriftController {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly drift: DriftService,
  ) {}

  @Get()
  async list(@CurrentUser() user: RequestUser, @Query("domain") domain?: string, @Query("type") type?: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.drift.listDrift(user, ws.id, { domain, type });
  }
}

@Controller("attack-surface")
export class AttackSurfaceController {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly drift: DriftService,
  ) {}

  @Get("changes")
  async changes(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.drift.listAttackSurfaceChanges(user, ws.id);
  }
}

@Controller("workflows")
export class WorkflowsController {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly workflows: WorkflowService,
  ) {}

  @Post()
  async create(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.workflows.createWorkflow(user, ws.id, parseOrThrow(createWorkflowSchema, body ?? {}));
  }

  @Get()
  async list(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.workflows.listWorkflows(user, ws.id);
  }

  @Get("executions")
  async executions(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.workflows.listExecutions(user, ws.id);
  }

  @Patch(":id")
  async update(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.workflows.updateWorkflow(user, ws.id, id, parseOrThrow(updateWorkflowSchema, body ?? {}));
  }
}

@Controller("notifications")
export class NotificationsController {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly notifications: NotificationRouterService,
  ) {}

  @Get()
  async list(@CurrentUser() user: RequestUser, @Query("channel") channel?: string, @Query("status") status?: string) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.notifications.listNotifications(user, ws.id, { channel, status });
  }

  @Post("policies")
  async createPolicy(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.notifications.createPolicy(user, ws.id, parseOrThrow(notificationPolicySchema, body ?? {}));
  }

  @Get("policies")
  async listPolicies(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.notifications.listPolicies(user, ws.id);
  }

  @Patch("policies/:id")
  async updatePolicy(@CurrentUser() user: RequestUser, @Param("id") id: string, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.notifications.updatePolicy(user, ws.id, id, (body ?? {}) as Record<string, unknown>);
  }

  @Post("escalation-policies")
  async createEscalation(@CurrentUser() user: RequestUser, @Body() body: unknown) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.notifications.createEscalationPolicy(user, ws.id, parseOrThrow(escalationPolicySchema, body ?? {}));
  }

  @Get("escalation-policies")
  async listEscalations(@CurrentUser() user: RequestUser) {
    const ws = await resolveWorkspace(this.prisma, user);
    return this.notifications.listEscalationPolicies(user, ws.id);
  }
}
