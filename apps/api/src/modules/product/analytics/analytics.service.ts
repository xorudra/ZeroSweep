import { Inject, Injectable } from "@nestjs/common";
import {
  PRODUCT_ANALYTICS_EVENTS, sanitizeAnalyticsProperties, type ProductAnalyticsEventType,
} from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { ProductConfigService } from "../product-config.service";

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * ProductAnalyticsService (Prompt 40 §141–§147).
 *
 * Privacy-conscious by construction: only the closed set of aggregate
 * product events (§142) is recordable, and every property bag passes
 * the §143 sanitizer — targets, vulnerability evidence, credentials,
 * tokens and finding payloads can never be stored here (§229). This is
 * product-usage health metadata (§146), NOT a customer security score
 * (§147). When telemetry is disabled in deployment configuration
 * (§144/§145 — the default), recording is a no-op.
 */
@Injectable()
export class ProductAnalyticsService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly config: ProductConfigService,
  ) {}

  async record(organizationId: string | null, type: ProductAnalyticsEventType, properties: Record<string, unknown> = {}): Promise<{ recorded: boolean; droppedKeys: string[] }> {
    if (!(PRODUCT_ANALYTICS_EVENTS as readonly string[]).includes(type)) return { recorded: false, droppedKeys: [] };
    const { properties: safe, droppedKeys } = sanitizeAnalyticsProperties(properties);
    if (!this.config.telemetryEnabled()) return { recorded: false, droppedKeys };
    await (this.prisma as any).productAnalyticsEvent.create({
      data: { organizationId, type, properties: safe as never },
    });
    return { recorded: true, droppedKeys };
  }

  /** Aggregate counts for the platform control plane (§146) — counts only, no tenant content. */
  async aggregateCounts(): Promise<Record<string, number>> {
    const rows = await (this.prisma as any).productAnalyticsEvent.findMany({}).catch(() => []);
    const counts: Record<string, number> = {};
    for (const row of rows as any[]) counts[row.type] = (counts[row.type] ?? 0) + 1;
    return counts;
  }
}
