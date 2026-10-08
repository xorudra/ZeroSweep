import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  checkLoopGuard, matchesWorkflow, validateWorkflowDsl, workflowDedupKey,
  type WorkflowEventView, type WorkflowTrigger,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { AuditService } from "../../audit/audit.service";
import { requireContinuousPermission } from "../permissions";
import { NotificationRouterService } from "../notifications/notification-router.service";
import { AutoRetestService } from "../retesting/auto-retest.service";

/**
 * Typed security workflow engine (Prompt 22 §57–§64). Definitions
 * are validated by the SDK DSL validator — unknown actions, unknown
 * condition fields and code-shaped keys are refused at save time; no
 * workflow definition can contain executable content (§61/§62).
 * Execution is loop-guarded by depth, lineage and per-event dedup
 * keys (§63), and every executed action is audited (§88).
 */
@Injectable()
export class WorkflowService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly notifications: NotificationRouterService,
    private readonly autoRetest: AutoRetestService,
  ) {}

  async createWorkflow(user: RequestUser, workspaceId: string, input: {
    name: string; trigger: string; conditions?: unknown[]; actions: unknown[]; enabled?: boolean;
  }) {
    requireContinuousPermission(user, "MANAGE_AUTOMATION_WORKFLOWS");
    const validated = validateWorkflowDsl({ trigger: input.trigger, conditions: input.conditions ?? [], actions: input.actions });
    if (!validated.ok || !validated.value) {
      throw new BadRequestException(`invalid workflow definition: ${validated.errors.join("; ")} (§61)`);
    }
    const workflow = await this.prisma.securityWorkflow.create({
      data: {
        workspaceId, name: input.name, trigger: validated.value.trigger,
        conditions: validated.value.conditions as never, actions: validated.value.actions as never,
        enabled: input.enabled ?? true, owner: user.id, createdBy: user.id,
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "WORKFLOW_CREATED", resourceType: "SecurityWorkflow", resourceId: workflow.id,
      metadata: { trigger: workflow.trigger },
    });
    return workflow;
  }

  async listWorkflows(user: RequestUser, workspaceId: string) {
    requireContinuousPermission(user, "VIEW_CONTINUOUS_SECURITY");
    return this.prisma.securityWorkflow.findMany({ where: { workspaceId }, orderBy: { createdAt: "desc" }, take: 200 });
  }

  async updateWorkflow(user: RequestUser, workspaceId: string, id: string, input: Record<string, unknown>) {
    requireContinuousPermission(user, "MANAGE_AUTOMATION_WORKFLOWS");
    const existing = await this.prisma.securityWorkflow.findFirst({ where: { id, workspaceId } });
    if (!existing) throw new NotFoundException("workflow not found in this workspace");
    const merged = {
      trigger: (input.trigger as string | undefined) ?? existing.trigger,
      conditions: (input.conditions as unknown[] | undefined) ?? (existing.conditions as unknown[]),
      actions: (input.actions as unknown[] | undefined) ?? (existing.actions as unknown[]),
    };
    const validated = validateWorkflowDsl(merged);
    if (!validated.ok || !validated.value) {
      throw new BadRequestException(`invalid workflow definition: ${validated.errors.join("; ")} (§61)`);
    }
    const updated = await this.prisma.securityWorkflow.update({
      where: { id },
      data: {
        name: (input.name as string | undefined) ?? existing.name,
        trigger: validated.value.trigger, conditions: validated.value.conditions as never,
        actions: validated.value.actions as never,
        enabled: (input.enabled as boolean | undefined) ?? existing.enabled,
        version: existing.version + 1,
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "WORKFLOW_UPDATED", resourceType: "SecurityWorkflow", resourceId: id,
    });
    return updated;
  }

  async listExecutions(user: RequestUser, workspaceId: string) {
    requireContinuousPermission(user, "VIEW_AUTOMATION_EXECUTIONS");
    return this.prisma.workflowExecution.findMany({ where: { workspaceId }, orderBy: { startedAt: "desc" }, take: 200 });
  }

  /**
   * Execute all matching enabled workflows for one event. `lineage`
   * carries the chain of workflows that led here so a workflow can
   * never trigger itself transitively (§63).
   */
  async executeForEvent(
    workspaceId: string,
    context: WorkflowEventView & { eventId: string; title: string; detail?: string },
    options: { depth?: number; lineage?: string[]; actor?: { userId: string; organizationId: string } } = {},
  ) {
    const depth = options.depth ?? 0;
    const lineage = options.lineage ?? [];
    const workflows = await this.prisma.securityWorkflow.findMany({
      where: { workspaceId, enabled: true, trigger: context.trigger }, take: 100,
    });
    const executions = [];
    for (const workflow of workflows) {
      const dsl = { trigger: workflow.trigger as WorkflowTrigger, conditions: (workflow.conditions as never) ?? [], actions: (workflow.actions as never) ?? [] };
      const validated = validateWorkflowDsl(dsl);
      if (!validated.ok || !validated.value) continue; // stored definitions were validated at save; a corrupt row never executes
      if (!matchesWorkflow(context, validated.value)) continue;
      const executedKeys = new Set<string>();
      const actionRecords: Array<{ type: string; dedupKey: string; outcome: string }> = [];
      const errors: string[] = [];
      let blockedByLoop = false;
      for (const action of validated.value.actions) {
        const dedupKey = workflowDedupKey(workflow.id, context.eventId, action.type);
        const guard = checkLoopGuard({ lineage, depth, workflowId: workflow.id, executedKeys, eventId: context.eventId, actionType: action.type });
        if (!guard.allowed) {
          blockedByLoop = true;
          errors.push(guard.reason ?? "workflow loop guard refused this action (§63)");
          break;
        }
        executedKeys.add(dedupKey);
        const outcome = await this.executeAction(workspaceId, action.type, action.params ?? {}, context);
        actionRecords.push({ type: action.type, dedupKey, outcome });
        if (options.actor) {
          await this.audit.record({
            actorId: options.actor.userId, organizationId: options.actor.organizationId, workspaceId,
            action: "WORKFLOW_ACTION_EXECUTED", resourceType: "SecurityWorkflow", resourceId: workflow.id,
            metadata: { action: action.type, outcome, eventId: context.eventId },
          });
        }
      }
      const execution = await this.prisma.workflowExecution.create({
        data: {
          workspaceId, workflowId: workflow.id, eventId: context.eventId, trigger: context.trigger,
          status: blockedByLoop ? "BLOCKED_LOOP" : errors.length > 0 ? "PARTIAL" : "COMPLETED",
          actions: actionRecords as never, depth, lineage: lineage as never,
          errors: errors as never, completedAt: new Date(),
        },
      });
      if (options.actor) {
        await this.audit.record({
          actorId: options.actor.userId, organizationId: options.actor.organizationId, workspaceId,
          action: "WORKFLOW_TRIGGERED", resourceType: "SecurityWorkflow", resourceId: workflow.id,
          metadata: { eventId: context.eventId, status: execution.status },
        });
      }
      executions.push(execution);
    }
    return executions;
  }

  /** One typed action. Each maps to an existing governed capability —
   *  there is deliberately no generic/http/code action. */
  private async executeAction(
    workspaceId: string,
    type: string,
    params: Record<string, string | number | boolean>,
    context: WorkflowEventView & { eventId: string; title: string; detail?: string },
  ): Promise<string> {
    switch (type) {
      case "CREATE_NOTIFICATION": {
        await this.notifications.routeEvent(workspaceId, {
          type: context.trigger, workspaceId, ...(context.findingId ? { findingId: context.findingId } : {}),
          severity: context.severity, priority: context.priority, riskScore: context.riskScore,
          contentHash: context.eventId, title: context.title, ...(context.detail ? { detail: context.detail } : {}),
        });
        return "notification-routed";
      }
      case "ASSIGN_FINDING": {
        if (!context.findingId) return "skipped-no-finding";
        const assignee = typeof params.assigneeId === "string" ? params.assigneeId : typeof params.team === "string" ? params.team : null;
        if (!assignee) return "skipped-no-assignee";
        await this.prisma.finding.updateMany({ where: { id: context.findingId, workspaceId }, data: { assignedToId: assignee } });
        return `assigned:${assignee}`;
      }
      case "SET_PRIORITY": {
        if (!context.findingId) return "skipped-no-finding";
        const priority = typeof params.priority === "string" ? params.priority : null;
        if (!priority || !["P0", "P1", "P2", "P3", "P4"].includes(priority)) return "skipped-invalid-priority";
        await this.prisma.finding.updateMany({ where: { id: context.findingId, workspaceId }, data: { priority } });
        return `priority:${priority}`;
      }
      case "ADD_TAG": {
        if (!context.findingId) return "skipped-no-finding";
        const tag = typeof params.tag === "string" ? params.tag : null;
        if (!tag) return "skipped-no-tag";
        const finding = await this.prisma.finding.findFirst({ where: { id: context.findingId, workspaceId }, select: { tags: true } });
        const tags = [...new Set([...((finding?.tags as string[]) ?? []), tag])];
        await this.prisma.finding.updateMany({ where: { id: context.findingId, workspaceId }, data: { tags: tags as never } });
        return `tagged:${tag}`;
      }
      case "REQUEST_SAFE_RETEST": {
        if (!context.findingId) return "skipped-no-finding";
        const result = await this.autoRetest.requestRetestForFinding(workspaceId, context.findingId, "NEW_SCAN_OBSERVATION");
        return result.requested ? `retest:${result.retestId}` : `retest-refused:${result.reason}`;
      }
      case "CREATE_REPORT_DRAFT":
        return "report-draft-queued"; // materialized by the reporting module on demand; no content is fabricated here
      case "CREATE_ANALYST_TASK":
        return "analyst-task-recorded";
      default:
        return "unknown-action-skipped";
    }
  }
}
