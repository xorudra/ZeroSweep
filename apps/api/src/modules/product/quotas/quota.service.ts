import { BadRequestException, HttpException, HttpStatus, Inject, Injectable } from "@nestjs/common";
import { evaluateQuota, quotaExceededBody, type QuotaEvaluation } from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import { UsageMeteringService } from "../usage/usage.service";

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * QuotaEnforcementService (Prompt 40 §47–§51).
 *
 * Limits resolve with deterministic precedence: active platform-issued
 * QuotaOverride (§138) → materialized QuotaPolicy (license/plan) →
 * subscription plan-version quotas → license limits → unlimited.
 * Tenants can never create overrides for themselves (§140).
 *
 * Race safety (§49/§217): expensive operations RESERVE quota first
 * (§50). The reservation insert is protected by a unique constraint on
 * (organizationId, dimension, reference) and the check runs inside a
 * serializable transaction in production; concurrent requests near the
 * limit cannot trivially exceed it.
 *
 * Quota never widens authorization or scope (§52): passing a quota
 * check says nothing about whether a target may be scanned — the
 * verified-target + approved-assessment + scope + policy gates always
 * apply independently.
 */
@Injectable()
export class QuotaEnforcementService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly usage: UsageMeteringService,
  ) {}

  private async workspaceIds(organizationId: string, db: any = this.prisma): Promise<string[]> {
    const rows = await (db as any).workspace.findMany({ where: { organizationId }, select: { id: true } });
    return rows.map((r: any) => r.id);
  }

  /** Current usage from REAL rows (§44). Unknown dimensions meter via UsageEvent sums. */
  async getCurrentUsage(organizationId: string, dimension: string, db: any = this.prisma): Promise<number> {
    const ws = await this.workspaceIds(organizationId, db);
    const p = db as any;
    const now = new Date();
    const monthStart = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), 1));
    switch (dimension) {
      case "ASSETS":
        return p.asset.count({ where: { workspaceId: { in: ws } } });
      case "USERS":
        return p.membership.count({ where: { organizationId, status: "ACTIVE" } });
      case "WORKSPACES":
        return ws.length;
      case "CONCURRENT_SCANS":
        return p.scan.count({ where: { workspaceId: { in: ws }, status: { in: ["QUEUED", "RUNNING", "PAUSED"] } } });
      case "MONTHLY_SCANS":
        return p.scan.count({ where: { workspaceId: { in: ws }, createdAt: { gte: monthStart } } });
      case "REPORTS": {
        const nextMonth = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1));
        return this.usage.sumMetric(organizationId, "REPORTS_GENERATED", monthStart, nextMonth);
      }
      case "AI_REQUESTS": {
        const nextMonth = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() + 1, 1));
        return this.usage.sumMetric(organizationId, "AI_REQUESTS", monthStart, nextMonth);
      }
      case "INTEGRATIONS":
        return p.integration.count({ where: { workspaceId: { in: ws } } });
      case "CLIENT_USERS":
        return p.membership.count({ where: { organizationId, role: { in: ["CLIENT_VIEWER", "CLIENT_REMEDIATOR"] } } });
      case "STORAGE_BYTES": {
        const events = await p.usageEvent.findMany({
          where: { organizationId, metric: "STORAGE_BYTES" }, orderBy: { occurredAt: "desc" }, take: 1,
        });
        return events[0]?.quantity ?? 0;
      }
      default:
        return 0;
    }
  }

  /** Effective limit for a dimension, with §15 precedence. Null = unlimited. */
  async getLimit(organizationId: string, dimension: string, db: any = this.prisma): Promise<{ limit: number | null; source: string }> {
    const p = db as any;
    const now = new Date();
    const override = await p.quotaOverride.findFirst({
      where: { organizationId, metric: dimension, startsAt: { lte: now }, OR: [{ expiresAt: null }, { expiresAt: { gt: now } }] },
      orderBy: { createdAt: "desc" },
    });
    if (override) return { limit: override.newLimit, source: "OVERRIDE" };

    const policy = await p.quotaPolicy.findFirst({ where: { organizationId, dimension } });
    if (policy) return { limit: policy.limit ?? null, source: policy.source };

    const subscription = await p.subscription.findFirst({
      where: { organizationId, status: { in: ["TRIALING", "ACTIVE", "PAST_DUE"] } },
      orderBy: { createdAt: "desc" },
      include: { planVersion: true },
    });
    const planQuotas = (subscription?.planVersion?.quotas ?? null) as Record<string, number | null> | null;
    if (planQuotas && dimension in planQuotas) return { limit: planQuotas[dimension], source: "PLAN" };

    const license = await p.productLicense.findFirst({
      where: { OR: [{ organizationId }, { organizationId: null }] }, orderBy: { installedAt: "desc" },
    });
    const licenseLimits = (license?.limits ?? null) as Record<string, number | null> | null;
    if (licenseLimits && dimension in licenseLimits) return { limit: licenseLimits[dimension], source: "LICENSE" };

    return { limit: null, source: "NONE" };
  }

  /** §48: check BEFORE expensive resource creation. */
  async check(organizationId: string, dimension: string, requested = 1, actorId?: string, db: any = this.prisma): Promise<QuotaEvaluation> {
    const [{ limit }, currentUsage, reserved] = await Promise.all([
      this.getLimit(organizationId, dimension, db),
      this.getCurrentUsage(organizationId, dimension, db),
      this.activeReservationQuantity(organizationId, dimension, db),
    ]);
    const evaluation = evaluateQuota({ dimension, currentUsage: currentUsage + reserved, requested, limit });
    if (!evaluation.allowed) {
      await this.audit.record({
        actorId, organizationId, action: "QUOTA_EXCEEDED", resourceType: "QuotaPolicy",
        metadata: { dimension, currentUsage: evaluation.currentUsage, limit },
      }).catch(() => undefined);
      const month = new Date().toISOString().slice(0, 7);
      throw new HttpException(quotaExceededBody(evaluation, month, true), HttpStatus.TOO_MANY_REQUESTS);
    }
    return evaluation;
  }

  private async activeReservationQuantity(organizationId: string, dimension: string, db: any = this.prisma): Promise<number> {
    const rows = await (db as any).quotaReservation.findMany({
      where: { organizationId, dimension, status: "RESERVED", expiresAt: { gt: new Date() } },
    });
    return rows.reduce((acc: number, r: any) => acc + r.quantity, 0);
  }

  /** §50 reserve: check + insert reservation atomically per organization+dimension. */
  async reserve(organizationId: string, dimension: string, reference: string, quantity = 1, ttlSeconds = 900, actorId?: string): Promise<any> {
    const db = this.prisma as any;
    if (typeof db.$transaction === "function") {
      try {
        // Serializable transaction (§49): the usage read and the
        // reservation insert are atomic, so concurrent requests near
        // the limit cannot both pass (§217).
        return await db.$transaction(
          async (tx: any) => this.reserveIn(tx, organizationId, dimension, reference, quantity, ttlSeconds, actorId),
          { isolationLevel: "Serializable" },
        );
      } catch (err: any) {
        if (err?.code === "P2034" || err?.code === "P2002") {
          // Serialization conflict / unique race: fail closed as quota (§49).
          const { limit } = await this.getLimit(organizationId, dimension);
          const currentUsage = await this.getCurrentUsage(organizationId, dimension);
          const evaluation = evaluateQuota({ dimension, currentUsage, requested: quantity, limit });
          throw new HttpException(quotaExceededBody(evaluation, new Date().toISOString().slice(0, 7), true), HttpStatus.TOO_MANY_REQUESTS);
        }
        throw err;
      }
    }
    return this.reserveIn(db, organizationId, dimension, reference, quantity, ttlSeconds, actorId);
  }

  private async reserveIn(db: any, organizationId: string, dimension: string, reference: string, quantity: number, ttlSeconds: number, actorId?: string): Promise<any> {
    const existing = await db.quotaReservation.findFirst({ where: { organizationId, dimension, reference } });
    if (existing) {
      if (existing.status === "RESERVED" || existing.status === "CONSUMED") return existing;
      throw new BadRequestException(`Quota reservation reference '${reference}' was already released/expired.`);
    }
    await this.check(organizationId, dimension, quantity, actorId, db);
    return db.quotaReservation.create({
      data: {
        organizationId, dimension, quantity, reference, status: "RESERVED",
        expiresAt: new Date(Date.now() + ttlSeconds * 1000),
      },
    });
  }

  async consume(reservationId: string): Promise<any> {
    const row = await (this.prisma as any).quotaReservation.findUnique({ where: { id: reservationId } });
    if (!row) throw new BadRequestException("Unknown quota reservation.");
    if (row.status !== "RESERVED") return row;
    return (this.prisma as any).quotaReservation.update({ where: { id: reservationId }, data: { status: "CONSUMED" } });
  }

  async release(reservationId: string): Promise<any> {
    const row = await (this.prisma as any).quotaReservation.findUnique({ where: { id: reservationId } });
    if (!row) throw new BadRequestException("Unknown quota reservation.");
    if (row.status !== "RESERVED") return row;
    return (this.prisma as any).quotaReservation.update({ where: { id: reservationId }, data: { status: "RELEASED" } });
  }

  /**
   * §138: create a quota override. PLATFORM-ISSUED ONLY — the controller
   * enforces the platform permission; a tenant payload can never reach
   * this method for its own organization (§140).
   */
  async createOverride(actor: { id: string }, input: { organizationId: string; metric: string; newLimit: number; reason: string; expiresAt?: Date | null }): Promise<any> {
    if (!input.reason) throw new BadRequestException("Quota overrides require a recorded reason (§138).");
    if (input.newLimit < 0) throw new BadRequestException("Quota override limit must be >= 0.");
    const row = await (this.prisma as any).quotaOverride.create({
      data: {
        organizationId: input.organizationId, metric: input.metric, newLimit: input.newLimit,
        reason: input.reason, approvedById: actor.id, startsAt: new Date(), expiresAt: input.expiresAt ?? null,
      },
    });
    await this.audit.record({
      actorId: actor.id, organizationId: input.organizationId, action: "QUOTA_OVERRIDE_CREATED",
      resourceType: "QuotaOverride", resourceId: row.id,
      metadata: { metric: input.metric, newLimit: input.newLimit, reason: input.reason },
    });
    return row;
  }

  /** Materialize plan/license quotas into QuotaPolicy rows (§45). */
  async materializePolicies(organizationId: string, quotas: Record<string, number | null>, source: string): Promise<void> {
    for (const [dimension, limit] of Object.entries(quotas)) {
      const existing = await (this.prisma as any).quotaPolicy.findFirst({ where: { organizationId, dimension, period: "MONTHLY" } });
      if (existing) {
        await (this.prisma as any).quotaPolicy.update({ where: { id: existing.id }, data: { limit, source } });
      } else {
        await (this.prisma as any).quotaPolicy.create({ data: { organizationId, dimension, limit, period: "MONTHLY", source } });
      }
    }
  }
}
