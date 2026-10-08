import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  IntegrationNotConfiguredError,
  JiraConnector,
  detectTicketConflicts,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireIntegrationPermission } from "../permissions";
import { IntegrationTransportFactory } from "../core/transport";
import { IntegrationsService } from "../core/integrations.service";
import { CicdService } from "../cicd/cicd.service";
import type { CreateJiraMappingBody, CreateTicketBody, ResolveConflictBody } from "../dto/schemas";

type Row = Record<string, unknown>;

/**
 * Remediation tickets (Prompt 24 §46–§54). Creation is idempotent
 * per (finding, integration) — the same workflow can never mint two
 * tickets for one finding (§49/§124). Bidirectional sync compares
 * against the last-synced snapshot: genuine two-sided changes become
 * TicketSyncConflicts for an analyst (§53/§54/§126).
 *
 * §52 is enforced structurally: sync writes ONLY ticket fields. The
 * finding lifecycle is never read from, or written by, a ticket
 * status — a CLOSED ticket leaves the finding exactly where the
 * platform's evidence/retest policy put it (§125).
 */
@Injectable()
export class TicketsService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly transports: IntegrationTransportFactory,
    private readonly integrations: IntegrationsService,
    private readonly cicd: CicdService,
  ) {}

  /* ------------------------------ mappings ------------------------------ */

  async createMapping(user: RequestUser, workspaceId: string, body: CreateJiraMappingBody) {
    requireIntegrationPermission(user, "MANAGE_TICKETING_INTEGRATIONS");
    const integration = await this.integrations.own(user, workspaceId, body.integrationId as string);
    if (integration.type !== "JIRA") throw new BadRequestException("Project mappings apply to JIRA integrations (§47)");
    return this.prisma.jiraProjectMapping.create({
      data: {
        workspaceId,
        integrationId: integration.id as string,
        findingType: (body.findingType as string) ?? null,
        team: (body.team as string) ?? null,
        assetGroup: (body.assetGroup as string) ?? null,
        projectKey: body.projectKey,
        issueType: (body.issueType as string) ?? "Task",
        createdBy: user.id,
      },
    });
  }

  async listMappings(user: RequestUser, workspaceId: string) {
    requireIntegrationPermission(user, "VIEW_INTEGRATIONS");
    return this.prisma.jiraProjectMapping.findMany({
      where: { workspaceId },
      orderBy: { createdAt: "desc" },
    });
  }

  /* ------------------------------ creation ------------------------------ */

  async createTicketForFinding(user: RequestUser, workspaceId: string, findingId: string, body: CreateTicketBody) {
    requireIntegrationPermission(user, "MANAGE_TICKETING_INTEGRATIONS");
    const finding = await this.prisma.finding.findFirst({ where: { id: findingId, workspaceId } });
    if (!finding) throw new NotFoundException("Finding not found");
    const mapping = await this.resolveMapping(workspaceId, finding as Row, body.integrationId as string | undefined);
    if (!mapping) {
      throw new BadRequestException("No Jira project mapping matches this finding — configure a mapping before creating tickets (§47)");
    }
    const integrationId = mapping.integrationId as string;
    const existing = await this.prisma.remediationTicket.findFirst({
      where: { integrationId, findingId },
    });
    if (existing) {
      // §49/§124: exactly one ticket per (finding, integration).
      return { ticket: existing, created: false, duplicatePrevented: true };
    }
    const integration = await this.integrations.own(user, workspaceId, integrationId);
    const connector = new JiraConnector(
      (integration.configuration ?? integration.config ?? {}) as Record<string, unknown>,
      this.transports.forIntegration(integration as Row & { type: string }),
    );
    const ticket = await this.prisma.remediationTicket.create({
      data: {
        workspaceId, findingId, integrationId,
        status: "OPEN", syncState: "PENDING",
        lastSyncedStatus: "OPEN",
        createdBy: user.id,
      },
    });
    try {
      const created = await connector.createIssue(this.cicd.toSanitizedView(finding as Row), {
        projectKey: mapping.projectKey as string,
        issueType: (mapping.issueType as string) ?? "Task",
      });
      const base = ((integration.configuration ?? integration.config ?? {}) as Row).baseUrl as string | undefined;
      const updated = await this.prisma.remediationTicket.update({
        where: { id: ticket.id },
        data: {
          externalId: created.externalId,
          externalKey: created.externalKey,
          externalUrl: base ? `${base.replace(/\/$/, "")}/browse/${created.externalKey}` : null,
          syncState: "IN_SYNC",
          lastSyncedAt: new Date(),
        },
      });
      await this.audit.record({
        actorId: user.id, organizationId: user.organizationId, workspaceId,
        action: "REMEDIATION_TICKET_CREATED", resourceType: "RemediationTicket", resourceId: ticket.id as string,
        metadata: { findingId, externalKey: created.externalKey },
      });
      return { ticket: updated, created: true };
    } catch (err) {
      if (err instanceof IntegrationNotConfiguredError) {
        // The local ticket record exists (PENDING); the external side
        // is honestly NOT_CONFIGURED — no fake external key is minted.
        const updated = await this.prisma.remediationTicket.update({
          where: { id: ticket.id },
          data: { syncState: "NOT_CONFIGURED" },
        });
        return { ticket: updated, created: true, externalStatus: "NOT_CONFIGURED" as const };
      }
      throw err;
    }
  }

  /* -------------------------------- sync -------------------------------- */

  async syncTicket(user: RequestUser, workspaceId: string, ticketId: string) {
    requireIntegrationPermission(user, "MANAGE_TICKETING_INTEGRATIONS");
    const ticket = await this.prisma.remediationTicket.findFirst({ where: { id: ticketId, workspaceId } });
    if (!ticket) throw new NotFoundException("Ticket not found");
    if (!ticket.externalKey) {
      return { ticket, synced: false, detail: "ticket has no external issue yet (NOT_CONFIGURED or pending creation)" };
    }
    const integration = await this.integrations.own(user, workspaceId, ticket.integrationId as string);
    const connector = new JiraConnector(
      (integration.configuration ?? integration.config ?? {}) as Record<string, unknown>,
      this.transports.forIntegration(integration as Row & { type: string }),
    );
    let external: { status: string; statusName: string; assigneeReference?: string } | null;
    try {
      external = await connector.getIssue(ticket.externalKey as string);
    } catch (err) {
      if (err instanceof IntegrationNotConfiguredError) {
        return { ticket, synced: false, detail: "NOT_CONFIGURED — Jira transport is not wired in this deployment" };
      }
      throw err;
    }
    if (!external) return { ticket, synced: false, detail: "external issue not found" };

    const finding = await this.prisma.finding.findFirst({ where: { id: ticket.findingId, workspaceId } });
    // The LOCAL side of the comparison is the ticket's own mapped
    // status + the finding's assignee (the analyst-owned fields).
    const local = {
      status: ticket.status as string,
      assigneeReference: (finding?.assignedToId as string) ?? null,
    };
    const lastSynced = {
      status: (ticket.lastSyncedStatus as string) ?? (ticket.status as string),
      assigneeReference: (ticket.lastSyncedAssignee as string) ?? null,
    };
    const externalSide = { status: external.status, assigneeReference: external.assigneeReference ?? null };
    const { conflicts, externalChanged } = detectTicketConflicts({ local, external: externalSide, lastSynced });

    for (const conflict of conflicts) {
      const open = await this.prisma.ticketSyncConflict.findFirst({
        where: { ticketId: ticket.id, field: conflict.field, status: "OPEN" },
      });
      if (!open) {
        await this.prisma.ticketSyncConflict.create({
          data: {
            workspaceId, ticketId: ticket.id, findingId: ticket.findingId,
            field: conflict.field, localValue: conflict.localValue, externalValue: conflict.externalValue,
            status: "OPEN",
          },
        });
      }
      await this.audit.record({
        actorId: user.id, organizationId: user.organizationId, workspaceId,
        action: "TICKET_SYNC_CONFLICT_DETECTED", resourceType: "RemediationTicket", resourceId: ticket.id as string,
        metadata: { field: conflict.field },
      }).catch(() => undefined);
    }

    if (conflicts.length > 0) {
      const updated = await this.prisma.remediationTicket.update({
        where: { id: ticket.id },
        data: { syncState: "CONFLICT", externalStatus: external.statusName },
      });
      return { ticket: updated, synced: false, conflicts };
    }

    if (externalChanged) {
      // §51/§52: the external status updates the TICKET only. The
      // finding's lifecycleStatus is deliberately untouched here —
      // resolution requires evidence/retest, not a ticket state.
      const updated = await this.prisma.remediationTicket.update({
        where: { id: ticket.id },
        data: {
          status: externalSide.status,
          externalStatus: external.statusName,
          assigneeReference: externalSide.assigneeReference,
          lastSyncedStatus: externalSide.status,
          lastSyncedAssignee: externalSide.assigneeReference,
          lastSyncedAt: new Date(),
          syncState: "IN_SYNC",
        },
      });
      await this.audit.record({
        actorId: user.id, organizationId: user.organizationId, workspaceId,
        action: "REMEDIATION_TICKET_SYNCED", resourceType: "RemediationTicket", resourceId: ticket.id as string,
        metadata: { externalStatus: external.statusName, mappedStatus: externalSide.status, findingLifecycleChanged: false },
      });
      return { ticket: updated, synced: true, conflicts: [] };
    }

    const updated = await this.prisma.remediationTicket.update({
      where: { id: ticket.id },
      data: { lastSyncedAt: new Date(), syncState: "IN_SYNC", externalStatus: external.statusName },
    });
    return { ticket: updated, synced: true, conflicts: [] };
  }

  async resolveConflict(user: RequestUser, workspaceId: string, conflictId: string, body: ResolveConflictBody) {
    requireIntegrationPermission(user, "MANAGE_TICKETING_INTEGRATIONS");
    const conflict = await this.prisma.ticketSyncConflict.findFirst({ where: { id: conflictId, workspaceId } });
    if (!conflict) throw new NotFoundException("Ticket sync conflict not found");
    const resolution = body.resolution as string;
    const updated = await this.prisma.ticketSyncConflict.update({
      where: { id: conflictId },
      data: { status: resolution, resolvedBy: user.id, resolvedAt: new Date() },
    });
    // Applying the decision updates the TICKET (and its sync
    // baseline) — never the finding lifecycle (§52/§53).
    if (conflict.field === "status") {
      const value = resolution === "RESOLVED_TAKE_EXTERNAL" ? conflict.externalValue : conflict.localValue;
      await this.prisma.remediationTicket.update({
        where: { id: conflict.ticketId },
        data: { status: value as string, lastSyncedStatus: value as string, syncState: "IN_SYNC" },
      }).catch(() => undefined);
    }
    return updated;
  }

  async listTickets(user: RequestUser, workspaceId: string) {
    requireIntegrationPermission(user, "VIEW_INTEGRATIONS");
    const tickets = await this.prisma.remediationTicket.findMany({
      where: { workspaceId },
      orderBy: { updatedAt: "desc" },
      take: 200,
    });
    const conflicts = await this.prisma.ticketSyncConflict.findMany({
      where: { workspaceId, status: "OPEN" },
    });
    return {
      tickets,
      openConflicts: conflicts,
    };
  }

  private async resolveMapping(workspaceId: string, finding: Row, integrationId?: string): Promise<Row | null> {
    const mappings = await this.prisma.jiraProjectMapping.findMany({
      where: { workspaceId, ...(integrationId ? { integrationId } : {}) },
      orderBy: { createdAt: "asc" },
    }) as Row[];
    const specific = mappings.find((m) =>
      (m.findingType && (finding.vulnClass as string) === m.findingType) ||
      (m.team && (finding.assignedToTeam as string) === m.team),
    );
    return specific ?? mappings.find((m) => !m.findingType && !m.team && !m.assetGroup) ?? mappings[0] ?? null;
  }
}
