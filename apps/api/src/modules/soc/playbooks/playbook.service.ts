import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import { getPlaybookTemplate, PLAYBOOK_TEMPLATES, validatePlaybookSteps } from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireSocPermission } from "../permissions";
import { IncidentService } from "../incidents/incident.service";
import type { Row } from "../helpers";

interface StepState { key: string; category: string; status: string; completedAt?: string; note?: string }

/**
 * Playbook engine (Prompt 28 §83–§89). Playbooks are the shipped
 * declarative templates (validated by the SDK — a step carrying any
 * executable field is rejected, §150). A run pins the template
 * version (§87) and walks steps one at a time; steps in the
 * EXECUTE_APPROVED_RESPONSE category never execute anything here —
 * they point at the response engine, whose approval policy is the
 * only execution path (§96).
 */
@Injectable()
export class PlaybookService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly incidents: IncidentService,
  ) {}

  templates(user: RequestUser) {
    requireSocPermission(user, "VIEW_SOC");
    return { playbooks: PLAYBOOK_TEMPLATES };
  }

  async start(user: RequestUser, workspaceId: string, incidentId: string, playbookKey: string) {
    requireSocPermission(user, "MANAGE_PLAYBOOKS");
    await this.incidents.getIncident(user, workspaceId, incidentId);
    const template = getPlaybookTemplate(playbookKey);
    if (!template) throw new NotFoundException(`Playbook template ${playbookKey} not found`);
    const validation = validatePlaybookSteps(template.steps);
    if (!validation.ok) throw new BadRequestException({ message: "Playbook template failed validation", errors: validation.errors });
    const stepsState: StepState[] = template.steps.map((s, i) => ({
      key: s.key, category: s.category, status: i === 0 ? "IN_PROGRESS" : "PENDING",
    }));
    const run = await this.prisma.incidentPlaybookRun.create({
      data: {
        organizationId: user.organizationId, workspaceId, incidentId,
        playbookKey: template.key, playbookVersion: template.version,
        status: "RUNNING", currentStepKey: template.steps[0].key,
        stepsState: stepsState as never, startedBy: user.id,
      },
    });
    await this.incidents.addTimeline(workspaceId, incidentId, "SYSTEM",
      `Playbook started: ${template.title} v${template.version}`, { runId: run.id }, user.id);
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "PLAYBOOK_STARTED", resourceType: "IncidentPlaybookRun", resourceId: run.id as string,
      metadata: { playbookKey, version: template.version, incidentId },
    });
    return run;
  }

  async advance(user: RequestUser, workspaceId: string, runId: string, body: { stepKey: string; note?: string }) {
    requireSocPermission(user, "MANAGE_PLAYBOOKS");
    const run = await this.prisma.incidentPlaybookRun.findFirst({ where: { id: runId, workspaceId } });
    if (!run) throw new NotFoundException("Playbook run not found in this workspace");
    const row = run as Row;
    if (row.status !== "RUNNING") throw new BadRequestException(`Playbook run is ${row.status}`);
    if (row.currentStepKey !== body.stepKey) {
      throw new BadRequestException(`Current step is ${row.currentStepKey} — steps complete in order (§88)`);
    }
    const stepsState = (row.stepsState as StepState[]).map((s) =>
      s.key === body.stepKey ? { ...s, status: "COMPLETED", completedAt: new Date().toISOString(), note: body.note } : s);
    const next = stepsState.find((s) => s.status === "PENDING");
    if (next) next.status = "IN_PROGRESS";
    const completed = !next;
    const updated = await this.prisma.incidentPlaybookRun.update({
      where: { id: runId },
      data: {
        stepsState: stepsState as never,
        currentStepKey: next?.key ?? null,
        status: completed ? "COMPLETED" : "RUNNING",
        completedAt: completed ? new Date() : undefined,
      } as never,
    });
    await this.incidents.addTimeline(workspaceId, row.incidentId as string, "SYSTEM",
      `Playbook step completed: ${body.stepKey}${completed ? " — playbook complete" : ""}`,
      { runId, stepKey: body.stepKey }, user.id);
    if (completed) {
      await this.audit.record({
        actorId: user.id, organizationId: user.organizationId, workspaceId,
        action: "PLAYBOOK_COMPLETED", resourceType: "IncidentPlaybookRun", resourceId: runId,
        metadata: { incidentId: row.incidentId },
      });
    }
    return updated;
  }

  async listRuns(user: RequestUser, workspaceId: string, incidentId: string) {
    requireSocPermission(user, "VIEW_INCIDENTS");
    await this.incidents.getIncident(user, workspaceId, incidentId);
    const items = await this.prisma.incidentPlaybookRun.findMany({
      where: { workspaceId, incidentId }, orderBy: { startedAt: "desc" },
    });
    return { items, total: items.length };
  }
}
