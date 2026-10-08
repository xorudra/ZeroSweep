import { BadRequestException, Inject, Injectable } from "@nestjs/common";
import {
  buildTicketPayload, isWorkItemStale, workItemIdempotencyKey, type TicketPayload,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { CaseStateService } from "./case-state.service";
import { requireRemediationPermission } from "./permissions";

export interface ExternalTicketResult {
  externalId: string;
  externalUrl?: string;
  status: string;
  assignee?: string;
}

/**
 * Provider seam (Prompt 31 §40). A provider either performs the call or
 * reports NOT_CONFIGURED — it never fabricates an external id. In this
 * deployment the Jira/GitHub/GitLab transports are the P24 connectors,
 * which are unwired until an admin registers an instance with a secret
 * REFERENCE — so the default provider honestly reports NOT_CONFIGURED
 * and work items record FAILED with retry state (§130).
 */
export interface RemediationTicketProvider {
  createTicket(payload: TicketPayload): Promise<ExternalTicketResult | { notConfigured: true; detail: string }>;
  fetchTicket(externalId: string): Promise<(ExternalTicketResult & { closed: boolean }) | { notConfigured: true; detail: string }>;
  healthCheck(): Promise<{ ok: boolean; detail: string }>;
}

export class UnconfiguredTicketProvider implements RemediationTicketProvider {
  async createTicket(): Promise<{ notConfigured: true; detail: string }> {
    return { notConfigured: true, detail: "ticket provider transport is NOT_CONFIGURED in this deployment (P24 connector unwired)" };
  }
  async fetchTicket(): Promise<{ notConfigured: true; detail: string }> {
    return { notConfigured: true, detail: "ticket provider transport is NOT_CONFIGURED in this deployment (P24 connector unwired)" };
  }
  async healthCheck(): Promise<{ ok: boolean; detail: string }> {
    return { ok: false, detail: "NOT_CONFIGURED" };
  }
}

export const TICKET_PROVIDERS = "REMEDIATION_TICKET_PROVIDERS";
export type TicketProviderRegistry = Map<string, RemediationTicketProvider>;

type WorkItemRow = Awaited<ReturnType<PrismaClientLike["remediationWorkItem"]["findFirstOrThrow"]>>;

const PROVIDER_STATUS_MAP: Record<string, string> = {
  OPEN: "OPEN", NEW: "OPEN", TODO: "OPEN", "TO DO": "OPEN",
  IN_PROGRESS: "IN_PROGRESS", "IN PROGRESS": "IN_PROGRESS", DOING: "IN_PROGRESS",
  RESOLVED: "RESOLVED", DONE: "RESOLVED", CLOSED: "CLOSED", CANCELLED: "CLOSED",
};

/** Provider statuses map into canonical states (§48) — raw provider
 *  text is data, never a lifecycle instruction. */
export function mapProviderStatus(raw: string | null | undefined): string {
  if (!raw) return "OPEN";
  return PROVIDER_STATUS_MAP[raw.toUpperCase()] ?? "OPEN";
}

@Injectable()
export class RemediationTicketsService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly state: CaseStateService,
    @Inject(TICKET_PROVIDERS) private readonly providers: TicketProviderRegistry,
  ) {}

  private providerFor(name: string): RemediationTicketProvider {
    return this.providers.get(name) ?? new UnconfiguredTicketProvider();
  }

  /**
   * Create the canonical work item + (attempt) the external ticket
   * (§38–§46). Idempotent on the stable key: a retry returns the
   * existing work item. Provider failure leaves the work item in place
   * with FAILED + backoff — never a duplicate, never a lost item (§130).
   */
  async createTicket(
    user: RequestUser,
    workspaceId: string,
    caseId: string,
    input: { provider: string; integrationId?: string },
    now = new Date(),
  ) {
    requireRemediationPermission(user, "CREATE_REMEDIATION_TICKET");
    const kase = await this.state.getCase(workspaceId, caseId);
    const key = workItemIdempotencyKey(caseId, input.provider);
    const existing = await this.prisma.remediationWorkItem.findFirst({ where: { idempotencyKey: key } });
    if (existing) {
      if (existing.workspaceId !== workspaceId) throw new BadRequestException("work item key collision across workspaces");
      return { workItem: existing as WorkItemRow, created: false, duplicate: true };
    }
    const finding = await this.state.getFinding(workspaceId, kase.findingId);
    const payload = buildTicketPayload({
      caseId, dueAt: kase.dueAt,
      finding: {
        id: finding.id, title: finding.title, severity: finding.severity,
        priority: kase.priority ?? finding.priority, host: finding.host, endpoint: finding.endpoint,
        cve: finding.cve, cwe: finding.cwe,
        riskExplanation: (finding.riskExplanation as { summary?: string } | null)?.summary ?? finding.businessImpact ?? null,
        remediationSummary: finding.remediation ?? null,
      },
    });
    let item = await this.prisma.remediationWorkItem.create({
      data: {
        caseId, workspaceId, findingId: kase.findingId, idempotencyKey: key,
        provider: input.provider, integrationId: input.integrationId ?? null,
        status: "PENDING", payload: payload as never, createdBy: user.id,
      },
    }) as WorkItemRow;
    item = await this.attemptDelivery(user, workspaceId, item, payload, now);
    await this.state.emit(user, workspaceId, kase, "REMEDIATION_TICKET_CREATED", {
      workItemId: item.id, provider: input.provider, status: item.status,
    });
    return { workItem: item, created: true, duplicate: false };
  }

  private async attemptDelivery(
    user: RequestUser, workspaceId: string, item: WorkItemRow, payload: TicketPayload, now: Date,
  ): Promise<WorkItemRow> {
    const provider = this.providerFor(item.provider);
    try {
      const result = await provider.createTicket(payload);
      if ("notConfigured" in result) {
        return await this.prisma.remediationWorkItem.update({
          where: { id: item.id },
          data: {
            status: "FAILED", failureCount: item.failureCount + 1, lastError: result.detail,
            nextRetryAt: new Date(now.getTime() + 15 * 60 * 1000),
          },
        }) as WorkItemRow;
      }
      const updated = await this.prisma.remediationWorkItem.update({
        where: { id: item.id },
        data: {
          status: "CREATED", externalId: result.externalId, externalUrl: result.externalUrl ?? null,
          externalStatus: result.status, assignee: result.assignee ?? null, lastSyncedAt: now, lastError: null,
        },
      }) as WorkItemRow;
      // Mirror into the P24 ticket table so the integrations views and
      // the remediation views describe the same external ticket (§42).
      const integrationId = item.integrationId;
      if (integrationId) {
        await this.prisma.remediationTicket.upsert({
          where: { integrationId_findingId: { integrationId, findingId: item.findingId } },
          create: {
            workspaceId, findingId: item.findingId, integrationId,
            externalId: result.externalId, externalUrl: result.externalUrl ?? null,
            status: mapProviderStatus(result.status), externalStatus: result.status,
            assigneeReference: result.assignee ?? null, syncState: "IN_SYNC",
            lastSyncedStatus: mapProviderStatus(result.status), lastSyncedAt: now, createdBy: user.id,
          },
          update: {
            externalId: result.externalId, externalUrl: result.externalUrl ?? null,
            status: mapProviderStatus(result.status), externalStatus: result.status,
            syncState: "IN_SYNC", lastSyncedStatus: mapProviderStatus(result.status), lastSyncedAt: now,
          },
        });
      }
      return updated;
    } catch (err) {
      return await this.prisma.remediationWorkItem.update({
        where: { id: item.id },
        data: {
          status: "FAILED", failureCount: item.failureCount + 1,
          lastError: err instanceof Error ? err.message : "provider error",
          nextRetryAt: new Date(now.getTime() + Math.min(60, 15 * 2 ** item.failureCount) * 60 * 1000),
        },
      }) as WorkItemRow;
    }
  }

  /** Retry a FAILED work item (§130): same row, same key — the retry
   *  can never mint a second external ticket for the same case (§131). */
  async retryTicket(user: RequestUser, workspaceId: string, workItemId: string, now = new Date()) {
    requireRemediationPermission(user, "CREATE_REMEDIATION_TICKET");
    const item = await this.prisma.remediationWorkItem.findFirst({ where: { id: workItemId, workspaceId } });
    if (!item) throw new BadRequestException("work item not found in this workspace");
    if (item.status !== "FAILED") throw new BadRequestException(`only FAILED work items can be retried (status ${item.status})`);
    const payload = item.payload as unknown as TicketPayload;
    const updated = await this.attemptDelivery(user, workspaceId, item as WorkItemRow, payload, now);
    return { workItem: updated };
  }

  /**
   * Ticket sync (§47–§49). Pulls provider status/assignee; a CLOSED
   * external ticket records a fix claim (source TICKET_SYNC) and moves
   * the case to FIX_CLAIMED — it NEVER marks anything verified (§132).
   */
  async syncWorkItem(user: RequestUser, workspaceId: string, workItemId: string, now = new Date()) {
    const item = await this.prisma.remediationWorkItem.findFirst({ where: { id: workItemId, workspaceId } });
    if (!item) throw new BadRequestException("work item not found in this workspace");
    if (!item.externalId) {
      return { workItem: item, synced: false, detail: "no external ticket exists yet (creation pending or NOT_CONFIGURED)" };
    }
    const provider = this.providerFor(item.provider);
    const remote = await provider.fetchTicket(item.externalId);
    if ("notConfigured" in remote) {
      return { workItem: item, synced: false, detail: remote.detail };
    }
    const mapped = mapProviderStatus(remote.status);
    const updated = await this.prisma.remediationWorkItem.update({
      where: { id: item.id },
      data: {
        status: remote.closed ? "CLOSED" : "SYNCED",
        externalStatus: remote.status, assignee: remote.assignee ?? item.assignee, lastSyncedAt: now,
      },
    }) as WorkItemRow;
    const kase = await this.state.getCase(workspaceId, item.caseId);
    await this.state.emit(user, workspaceId, kase, "REMEDIATION_TICKET_SYNCED", { workItemId: item.id, externalStatus: remote.status });
    let claim = null;
    if (remote.closed && ["IN_PROGRESS", "ASSIGNED", "PLANNED", "BLOCKED"].includes(kase.status)) {
      claim = await this.recordFixClaim(user, workspaceId, kase.id, {
        claimSource: "TICKET_SYNC",
        description: `external ${item.provider} ticket ${item.externalId} closed — fix claimed by ticket sync, verification still required (§49)`,
        workItemId: item.id,
      });
    }
    return { workItem: updated, synced: true, mappedStatus: mapped, fixClaim: claim };
  }

  /** §47 worker pass: sync every live work item + flag stale ones. */
  async syncWorkspace(user: RequestUser, workspaceId: string, now = new Date()) {
    const items = await this.prisma.remediationWorkItem.findMany({
      where: { workspaceId, status: { in: ["CREATED", "SYNCED", "FAILED"] } }, take: 500,
    });
    let synced = 0;
    let stale = 0;
    for (const item of items as WorkItemRow[]) {
      if (isWorkItemStale(item, now)) {
        await this.prisma.remediationWorkItem.update({ where: { id: item.id }, data: { status: "STALE" } });
        stale += 1;
        continue;
      }
      if (item.status === "FAILED") continue; // retries are explicit (§130)
      const result = await this.syncWorkItem(user, workspaceId, item.id, now);
      if (result.synced) synced += 1;
    }
    return { examined: items.length, synced, stale };
  }

  /**
   * Fix claims (§50/§51/§137). A claim moves the case to FIX_CLAIMED and
   * NOWHERE else — verification is a separate, later, governed act.
   */
  async recordFixClaim(user: RequestUser, workspaceId: string, caseId: string, input: {
    claimSource: string; description: string; workItemId?: string;
    deploymentRef?: string; commitRef?: string; patchRef?: string; evidence?: unknown;
  }) {
    if (input.claimSource === "MANUAL") requireRemediationPermission(user, "CLAIM_FIX");
    if (!input.description?.trim()) throw new BadRequestException("a fix claim requires a description of what changed (§50)");
    const kase = await this.state.getCase(workspaceId, caseId);
    const claim = await this.prisma.remediationFixClaim.create({
      data: {
        caseId, workspaceId, claimedBy: user.id, claimSource: input.claimSource,
        description: input.description, workItemId: input.workItemId ?? null,
        deploymentRef: input.deploymentRef ?? null, commitRef: input.commitRef ?? null,
        patchRef: input.patchRef ?? null, evidence: (input.evidence as never) ?? null,
      },
    });
    let updated = kase;
    if (["IN_PROGRESS", "BLOCKED", "ASSIGNED", "PLANNED"].includes(kase.status)) {
      updated = await this.state.transition(user, workspaceId, kase, {
        to: "FIX_CLAIMED", viaFixClaim: true, reason: input.description,
        evidence: { claimId: claim.id, source: input.claimSource },
      });
      // Mirror the P11 lifecycle: claimed ≠ resolved (§137). Only the
      // two from-states the VM machine allows into REMEDIATED are
      // mirrored, and the move is written to the finding history.
      const finding = await this.state.getFinding(workspaceId, kase.findingId);
      if (finding.lifecycleStatus === "IN_PROGRESS" || finding.lifecycleStatus === "CONFIRMED") {
        await this.prisma.finding.update({
          where: { id: finding.id }, data: { lifecycleStatus: "REMEDIATED" } as never,
        });
        await this.prisma.findingHistory.create({
          data: {
            findingId: finding.id, workspaceId, actorId: user.id, event: "REMEDIATION_FIX_CLAIMED",
            notes: input.description, metadata: { caseId, claimId: claim.id, from: finding.lifecycleStatus, to: "REMEDIATED" } as never,
          },
        });
      }
    } else {
      await this.state.emit(user, workspaceId, kase, "REMEDIATION_FIX_CLAIMED", { claimId: claim.id, source: input.claimSource });
    }
    return { case: updated, claim };
  }
}
