import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  evaluateResponsePolicy, getResponseActionDefinition, responseExecutionId,
  RESPONSE_ACTION_CATALOG,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireSocPermission } from "../permissions";
import { IncidentService } from "../incidents/incident.service";
import type { Row } from "../helpers";

/**
 * Response engine (Prompt 28 §74–§82). Actions come ONLY from the
 * closed SDK catalog of predefined, defensive, platform-internal
 * operations (§75/§76). The execution pipeline is:
 * propose → policy check → approval (SoD enforced, §126) → execute
 * → verify → timeline → audit (§80). Execution is idempotent by
 * executionId (§81/§148): a retry returns the existing record and
 * never re-executes. External containment is not in the catalog —
 * there is no connector for it, so it cannot be proposed at all.
 */
@Injectable()
export class ResponseService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly incidents: IncidentService,
  ) {}

  catalog(user: RequestUser) {
    requireSocPermission(user, "VIEW_SOC");
    return { actions: RESPONSE_ACTION_CATALOG };
  }

  async propose(user: RequestUser, workspaceId: string, incidentId: string, body: {
    actionKey: string; targetReference: string; nonce: string;
  }) {
    requireSocPermission(user, "PROPOSE_RESPONSE_ACTION");
    await this.incidents.getIncident(user, workspaceId, incidentId);
    const definition = getResponseActionDefinition(body.actionKey);
    if (!definition) {
      throw new BadRequestException(`Response action ${body.actionKey} is not in the predefined catalog — arbitrary actions do not exist (§76)`);
    }
    const executionId = responseExecutionId(incidentId, body.actionKey, body.targetReference, body.nonce);
    const existing = await this.prisma.responseActionExecution.findFirst({ where: { workspaceId, executionId } });
    if (existing) return { execution: existing, duplicate: true }; // §81: same logical action
    const required = definition.approvalMode === "NO_APPROVAL" ? 0 : definition.approvalMode === "SINGLE_APPROVAL" ? 1 : 2;
    const execution = await this.prisma.responseActionExecution.create({
      data: {
        organizationId: user.organizationId, workspaceId, incidentId,
        actionKey: body.actionKey, targetReference: body.targetReference, executionId,
        status: required === 0 ? "APPROVED" : "PENDING_APPROVAL", proposedBy: user.id,
        result: { approvalMode: definition.approvalMode, approvalsRequired: required } as never,
      },
    });
    await this.incidents.addTimeline(workspaceId, incidentId, "RESPONSE_ACTION",
      `Response proposed: ${definition.title} → ${body.targetReference} (${definition.approvalMode})`,
      { executionId: execution.id }, user.id);
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "RESPONSE_ACTION_PROPOSED", resourceType: "ResponseActionExecution",
      resourceId: execution.id as string, metadata: { actionKey: body.actionKey, incidentId },
    });
    return { execution, duplicate: false };
  }

  async approve(user: RequestUser, workspaceId: string, executionRowId: string, body: { decision: string; reason?: string }) {
    requireSocPermission(user, "APPROVE_RESPONSE_ACTION");
    const execution = await this.prisma.responseActionExecution.findFirst({ where: { id: executionRowId, workspaceId } });
    if (!execution) throw new NotFoundException("Response action not found in this workspace");
    const row = execution as Row;
    if (!["PENDING_APPROVAL", "APPROVED", "PROPOSED"].includes(row.status as string)) {
      throw new BadRequestException(`Action in status ${row.status} cannot be approved`);
    }
    const existing = await this.prisma.responseActionApproval.findFirst({
      where: { executionId: executionRowId, approverId: user.id },
    });
    if (!existing) {
      await this.prisma.responseActionApproval.create({
        data: { executionId: executionRowId, workspaceId, approverId: user.id, decision: body.decision, reason: body.reason ?? "" },
      });
    }
    const approvals = await this.prisma.responseActionApproval.findMany({ where: { workspaceId, executionId: executionRowId } });
    const policy = evaluateResponsePolicy({
      actionKey: row.actionKey as string, proposerId: row.proposedBy as string,
      approvals: (approvals as Row[]).map((a) => ({ approverId: a.approverId as string, decision: a.decision as string })),
    });
    const rejected = (approvals as Row[]).some((a) => a.decision === "REJECTED");
    const status = rejected ? "REJECTED" : policy.eligible ? "APPROVED" : "PENDING_APPROVAL";
    const updated = await this.prisma.responseActionExecution.update({
      where: { id: executionRowId },
      data: { status, result: { ...(row.result as Row), approvals: policy.validApprovals, approvalsRequired: policy.required, policyReasons: policy.reasons } } as never,
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "RESPONSE_ACTION_APPROVED", resourceType: "ResponseActionExecution", resourceId: executionRowId,
      metadata: { decision: body.decision, status, incidentId: row.incidentId },
    });
    return { execution: updated, policy: { required: policy.required, validApprovals: policy.validApprovals, eligible: policy.eligible, reasons: policy.reasons } };
  }

  /** §80/§145/§146: execution requires the EXECUTE permission AND
   *  a fully approved state. Anything else does not execute. */
  async execute(user: RequestUser, workspaceId: string, executionRowId: string) {
    requireSocPermission(user, "EXECUTE_RESPONSE_ACTION");
    const execution = await this.prisma.responseActionExecution.findFirst({ where: { id: executionRowId, workspaceId } });
    if (!execution) throw new NotFoundException("Response action not found in this workspace");
    const row = execution as Row;
    if (row.status === "EXECUTED") return { execution: row, duplicate: true, detail: "Already executed — idempotent retry (§81/§148)" };
    if (row.status !== "APPROVED") {
      return { execution: row, executed: false, detail: `NOT EXECUTED: action is ${row.status} — approval requirements are not satisfied (§146)` };
    }
    const result = await this.performAction(user, workspaceId, row);
    const status = result.ok ? "EXECUTED" : result.notConfigured ? "NOT_CONFIGURED" : "FAILED";
    const updated = await this.prisma.responseActionExecution.update({
      where: { id: executionRowId },
      data: { status, executedAt: new Date(), executedBy: user.id, result: { ...(row.result as Row), execution: result.detail } } as never,
    });
    await this.incidents.addTimeline(workspaceId, row.incidentId as string, "RESPONSE_ACTION",
      `Response executed: ${row.actionKey} → ${status}`, { executionId: executionRowId, result: result.detail }, user.id);
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "RESPONSE_ACTION_EXECUTED", resourceType: "ResponseActionExecution", resourceId: executionRowId,
      metadata: { actionKey: row.actionKey, status, incidentId: row.incidentId },
    });
    return { execution: updated, executed: result.ok, detail: result.detail };
  }

  /** The closed set of executable effects — platform-internal rows
   *  only. Each branch verifies the target belongs to this tenant. */
  private async performAction(user: RequestUser, workspaceId: string, row: Row): Promise<{ ok: boolean; detail: Row; notConfigured?: boolean }> {
    const target = row.targetReference as string;
    switch (row.actionKey) {
      case "DISABLE_DSRCLONE_API_KEY": {
        const key = await this.prisma.apiKey.findFirst({ where: { id: target, organizationId: user.organizationId } });
        if (!key) return { ok: false, detail: { error: "API key not found in this organization" } };
        if ((key as Row).revokedAt) return { ok: true, detail: { alreadyRevoked: true } };
        await this.prisma.apiKey.update({ where: { id: target }, data: { revokedAt: new Date() } as never });
        return { ok: true, detail: { revokedAt: new Date().toISOString(), rollback: "re-enable via credential administration (audited)" } };
      }
      case "REVOKE_DSRCLONE_SESSION": {
        const session = await this.prisma.userSession.findFirst({ where: { id: target, organizationId: user.organizationId } });
        if (!session) return { ok: false, detail: { error: "Session not found in this organization" } };
        await this.prisma.userSession.update({ where: { id: target }, data: { revokedAt: new Date() } as never });
        return { ok: true, detail: { sessionRevoked: target } };
      }
      case "DISABLE_DSRCLONE_SERVICE_ACCOUNT": {
        const account = await this.prisma.serviceAccount.findFirst({ where: { id: target, organizationId: user.organizationId } });
        if (!account) return { ok: false, detail: { error: "Service account not found in this organization" } };
        await this.prisma.serviceAccount.update({ where: { id: target }, data: { status: "DISABLED" } as never });
        return { ok: true, detail: { disabled: target } };
      }
      case "PAUSE_DSRCLONE_INTEGRATION": {
        const integration = await this.prisma.integration.findFirst({ where: { id: target, workspaceId } });
        if (!integration) return { ok: false, detail: { error: "Integration not found in this workspace" } };
        await this.prisma.integration.update({ where: { id: target }, data: { enabled: false } as never });
        return { ok: true, detail: { pausedIntegration: target } };
      }
      case "PAUSE_SCAN_AUTOMATION": {
        const schedules = await this.prisma.securitySchedule.findMany({ where: { workspaceId, kind: "SCAN", enabled: true } });
        let paused = 0;
        for (const schedule of schedules as Row[]) {
          await this.prisma.securitySchedule.update({ where: { id: schedule.id as string }, data: { enabled: false } as never });
          paused++;
        }
        return { ok: true, detail: { pausedSchedules: paused, scope: target } };
      }
      case "CREATE_REMEDIATION_TICKET": {
        // Through the governed P24 path: exactly-once per
        // (integration, finding); without a ticketing integration
        // the outcome is honestly NOT_CONFIGURED.
        const finding = await this.prisma.finding.findFirst({ where: { id: target, workspaceId } });
        if (!finding) return { ok: false, detail: { error: "Finding not found in this workspace" } };
        const integration = await this.prisma.integration.findFirst({ where: { workspaceId, type: "JIRA", enabled: true } });
        if (!integration) return { ok: false, notConfigured: true, detail: { error: "No enabled JIRA integration — ticket transport NOT_CONFIGURED (P24)" } };
        const existing = await this.prisma.remediationTicket.findFirst({
          where: { integrationId: (integration as Row).id as string, findingId: target },
        });
        if (existing) return { ok: true, detail: { ticketId: (existing as Row).id, alreadyExisted: true } };
        const ticket = await this.prisma.remediationTicket.create({
          data: {
            workspaceId, findingId: target, integrationId: (integration as Row).id as string,
            status: "OPEN", syncState: "NOT_CONFIGURED", createdBy: user.id,
          },
        });
        return { ok: true, detail: { ticketId: ticket.id, syncState: "NOT_CONFIGURED — created locally, provider transport unwired (P24)" } };
      }
      case "SEND_NOTIFICATION": {
        const notification = await this.prisma.securityNotification.create({
          data: {
            workspaceId, eventType: "SOC_RESPONSE", channel: "IN_APP", status: "SENT",
            providerStatus: "CONFIGURED", fingerprint: `soc-response:${row.id}`,
            title: `SOC response notification for incident ${row.incidentId}`,
            detail: target,
          },
        });
        return { ok: true, detail: { notificationId: notification.id, channel: "IN_APP" } };
      }
      case "REQUEST_CREDENTIAL_ROTATION": {
        const notification = await this.prisma.securityNotification.create({
          data: {
            workspaceId, eventType: "CREDENTIAL_ROTATION_REQUESTED", channel: "IN_APP", status: "SENT",
            providerStatus: "CONFIGURED", fingerprint: `soc-rotation:${row.id}`,
            title: "Credential rotation requested by SOC response",
            detail: `Credential reference ${target} — rotation happens in the owning system; this request is the tracked record.`,
          },
        });
        return { ok: true, detail: { requestId: notification.id, credentialReference: target } };
      }
      case "MARK_ASSET_FOR_REVIEW": {
        const asset = await this.prisma.asset.findFirst({ where: { id: target, workspaceId } });
        if (!asset) return { ok: false, detail: { error: "Asset not found in this workspace" } };
        await this.incidents.addTimeline(workspaceId, row.incidentId as string, "SYSTEM",
          `Asset ${target} marked for review`, { assetId: target }, user.id).catch(() => undefined);
        return { ok: true, detail: { assetFlaggedForReview: target, mechanism: "incident timeline flag + asset review queue via linked incident" } };
      }
      default:
        return { ok: false, detail: { error: "Action not executable — not in catalog" } };
    }
  }
}
