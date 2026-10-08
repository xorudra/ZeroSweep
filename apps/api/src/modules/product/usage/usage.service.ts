import { BadRequestException, Inject, Injectable } from "@nestjs/common";
import {
  USAGE_METRIC_DEFINITIONS, isUsageMetric, periodStart, type UsageMetric,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";

/* eslint-disable @typescript-eslint/no-explicit-any */

export interface RecordUsageInput {
  workspaceId?: string;
  metric: string;
  quantity?: number;
  source: string;
  reference?: string;
  idempotencyKey: string;
  occurredAt?: Date;
}

/**
 * UsageMeteringService (Prompt 40 §38). Raw UsageEvent rows are the
 * authoritative billable record (§44); aggregates are derived (§43).
 * Recording is idempotent on the caller's idempotency key (§42): a
 * retried job returns the original event and never double-charges
 * (§218). Tenants can only ever read their own usage (§133/§214) —
 * every query is scoped by the caller's organization id.
 */
@Injectable()
export class UsageMeteringService {
  constructor(@Inject(PRISMA) private readonly prisma: PrismaClientLike) {}

  async record(organizationId: string, input: RecordUsageInput): Promise<{ event: any; duplicate: boolean }> {
    if (!isUsageMetric(input.metric)) {
      throw new BadRequestException(`Unknown usage metric '${input.metric}'. Canonical metrics: ${Object.keys(USAGE_METRIC_DEFINITIONS).join(", ")} (§41).`);
    }
    if (!input.idempotencyKey) throw new BadRequestException("Usage events require an idempotencyKey (§42).");
    const existing = await (this.prisma as any).usageEvent.findUnique({ where: { idempotencyKey: input.idempotencyKey } });
    if (existing) {
      if (existing.organizationId !== organizationId) {
        throw new BadRequestException("Idempotency key already used by another organization.");
      }
      return { event: existing, duplicate: true };
    }
    const occurredAt = input.occurredAt ?? new Date();
    const event = await (this.prisma as any).usageEvent.create({
      data: {
        organizationId,
        workspaceId: input.workspaceId ?? null,
        metric: input.metric,
        quantity: input.quantity ?? 1,
        source: input.source,
        reference: input.reference ?? null,
        occurredAt,
        idempotencyKey: input.idempotencyKey,
      },
    });
    await this.bumpAggregate(organizationId, input.metric as UsageMetric, input.quantity ?? 1, occurredAt, "DAILY");
    await this.bumpAggregate(organizationId, input.metric as UsageMetric, input.quantity ?? 1, occurredAt, "BILLING_PERIOD");
    return { event, duplicate: false };
  }

  private async bumpAggregate(organizationId: string, metric: UsageMetric, quantity: number, occurredAt: Date, granularity: "DAILY" | "BILLING_PERIOD"): Promise<void> {
    const start = periodStart(occurredAt, granularity);
    const existing = await (this.prisma as any).usageAggregate.findFirst({
      where: { organizationId, metric, granularity, periodStart: start },
    });
    if (existing) {
      await (this.prisma as any).usageAggregate.update({ where: { id: existing.id }, data: { quantity: existing.quantity + quantity } });
    } else {
      await (this.prisma as any).usageAggregate.create({
        data: { organizationId, metric, granularity, periodStart: start, quantity },
      });
    }
  }

  /** Sum of raw events in a window — computed from real rows only (§44). */
  async sumMetric(organizationId: string, metric: string, from: Date, to: Date): Promise<number> {
    const events = await (this.prisma as any).usageEvent.findMany({
      where: { organizationId, metric, occurredAt: { gte: from, lt: to } },
    });
    return events.reduce((acc: number, e: any) => acc + e.quantity, 0);
  }

  /** Own-organization usage view (§107/§133). Unknown metrics report null, never invented numbers. */
  async getUsage(organizationId: string, from: Date, to: Date): Promise<Array<{ metric: string; definition: string; quantity: number }>> {
    const aggregates = await (this.prisma as any).usageAggregate.findMany({
      where: { organizationId, granularity: "DAILY", periodStart: { gte: from, lt: to } },
    });
    const byMetric = new Map<string, number>();
    for (const a of aggregates) byMetric.set(a.metric, (byMetric.get(a.metric) ?? 0) + a.quantity);
    return [...byMetric.entries()].map(([metric, quantity]) => ({
      metric,
      definition: USAGE_METRIC_DEFINITIONS[metric as UsageMetric] ?? "Derived metric.",
      quantity,
    }));
  }
}
