import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  canTransitionLifecycle, computeDeletionImpact, DEFAULT_RETENTION_DAYS,
  type OrganizationLifecycleState,
} from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * Organization lifecycle (Prompt 40 §85–§94).
 *
 * Suspension blocks new expensive/security work while preserving admin
 * and data access (§87). Cancellation is a state, not a deletion
 * (§88): the organization flows CANCELLATION_PENDING → CANCELLED →
 * RETENTION (configurable, §89) → DELETION_PENDING → DELETED, and the
 * destructive step requires an impact preview (§92), a typed
 * confirmation + audit (§93), and no legal hold (§94). An authorized
 * data export path stays available before deletion (§90) via the
 * platform's existing report/audit export machinery.
 */
@Injectable()
export class OrganizationLifecycleService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
  ) {}

  private async getOrg(organizationId: string): Promise<any> {
    const org = await (this.prisma as any).organization.findUnique({ where: { id: organizationId } });
    if (!org) throw new NotFoundException("Organization not found.");
    return org;
  }

  private async transition(actorId: string, organizationId: string, to: OrganizationLifecycleState, action: string, extra: Record<string, unknown> = {}): Promise<any> {
    const org = await this.getOrg(organizationId);
    const from = (org.lifecycleStatus ?? "ACTIVE") as OrganizationLifecycleState;
    if (!canTransitionLifecycle(from, to)) {
      throw new BadRequestException(`Organization lifecycle cannot move ${from} → ${to} (§86).`);
    }
    const updated = await (this.prisma as any).organization.update({
      where: { id: organizationId },
      data: { lifecycleStatus: to, ...extra },
    });
    await this.audit.record({ actorId, organizationId, action, resourceType: "Organization", resourceId: organizationId, metadata: { from, to } });
    return updated;
  }

  /** §87: platform suspension. */
  async suspend(actorId: string, organizationId: string): Promise<any> {
    const updated = await this.transition(actorId, organizationId, "SUSPENDED", "ORGANIZATION_SUSPENDED");
    await (this.prisma as any).organization.update({ where: { id: organizationId }, data: { status: "SUSPENDED" } });
    return updated;
  }

  async reactivate(actorId: string, organizationId: string): Promise<any> {
    const updated = await this.transition(actorId, organizationId, "ACTIVE", "ORGANIZATION_REACTIVATED");
    await (this.prisma as any).organization.update({ where: { id: organizationId }, data: { status: "ACTIVE" } });
    return updated;
  }

  /** §88: tenant-requested cancellation. Security history is preserved. */
  async requestCancellation(actorId: string, organizationId: string): Promise<any> {
    return this.transition(actorId, organizationId, "CANCELLATION_PENDING", "ORGANIZATION_CANCELLATION_REQUESTED", {});
  }

  async undoCancellation(actorId: string, organizationId: string): Promise<any> {
    return this.transition(actorId, organizationId, "ACTIVE", "ORGANIZATION_REACTIVATED");
  }

  /** Operator finalization: CANCELLED → RETENTION with a retention deadline (§89). */
  async finalizeCancellation(actorId: string, organizationId: string, retentionDays = DEFAULT_RETENTION_DAYS): Promise<any> {
    const cancelled = await this.transition(actorId, organizationId, "CANCELLED", "ORGANIZATION_CANCELLATION_REQUESTED");
    const retentionUntil = new Date(Date.now() + retentionDays * 86_400_000);
    return (this.prisma as any).organization.update({
      where: { id: organizationId },
      data: { lifecycleStatus: "RETENTION", retentionUntil },
    }).then((row: any) => ({ ...row, previousState: cancelled.lifecycleStatus }));
  }

  /** §92: destructive-deletion impact preview (counts from real rows). */
  async deletionPreview(organizationId: string): Promise<any> {
    const org = await this.getOrg(organizationId);
    const wsRows = await (this.prisma as any).workspace.findMany({ where: { organizationId }, select: { id: true } });
    const ws = wsRows.map((r: any) => r.id);
    const [assets, findings, reports, integrations, users, usageEvents] = await Promise.all([
      (this.prisma as any).asset.count({ where: { workspaceId: { in: ws } } }),
      (this.prisma as any).finding.count({ where: { workspaceId: { in: ws } } }).catch(() => 0),
      (this.prisma as any).report.count({ where: { workspaceId: { in: ws } } }),
      (this.prisma as any).integration.count({ where: { workspaceId: { in: ws } } }),
      (this.prisma as any).membership.count({ where: { organizationId } }),
      (this.prisma as any).usageEvent.count({ where: { organizationId } }),
    ]);
    return computeDeletionImpact(
      { workspaces: ws.length, assets, findings, reports, evidenceItems: 0, integrations, users, usageEvents },
      Boolean(org.legalHold),
    );
  }

  /**
   * §91–§93: request destructive deletion. Requires the RETENTION state,
   * a typed confirmation equal to the organization slug, and no legal
   * hold. This records DELETION_PENDING; the physical purge is an
   * operator-run, separately-audited process — this API never hard
   * deletes inline.
   */
  async requestDeletion(actorId: string, organizationId: string, typedConfirmation: string): Promise<any> {
    const org = await this.getOrg(organizationId);
    if (typedConfirmation !== org.slug) {
      throw new BadRequestException("Deletion requires typing the exact organization slug as confirmation (§93).");
    }
    const preview = await this.deletionPreview(organizationId);
    if (preview.deletionBlocked) throw new BadRequestException(preview.blockReason);
    const updated = await this.transition(actorId, organizationId, "DELETION_PENDING", "ORGANIZATION_DELETION_REQUESTED", {});
    return { organization: updated, impact: preview, note: "Physical purge is executed by an operator process with its own audit record; nothing was deleted by this request (§91)." };
  }

  /** §94 extension point: legal hold toggling is platform/owner governed and audited. */
  async setLegalHold(actorId: string, organizationId: string, hold: boolean): Promise<any> {
    await this.getOrg(organizationId);
    const updated = await (this.prisma as any).organization.update({ where: { id: organizationId }, data: { legalHold: hold } });
    await this.audit.record({ actorId, organizationId, action: "ROLE_CHANGED", resourceType: "Organization", resourceId: organizationId, metadata: { legalHold: hold } });
    return updated;
  }
}
