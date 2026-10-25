import { Inject, Injectable } from "@nestjs/common";
import { ABUSE_SIGNALS, evaluateAbuseResponse, type AbuseResponse, type AbuseSignal } from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";

/* eslint-disable @typescript-eslint/no-explicit-any */

/**
 * AbusePreventionService (Prompt 40 §169–§172). Records platform-safety
 * signals and evaluates the response ladder. Signals are indicators,
 * not proof of intent (§172): responses escalate warn → throttle →
 * block scan creation → require human review, and every state is
 * visible to platform operators. Nothing here deletes data or declares
 * guilt.
 */
@Injectable()
export class AbusePreventionService {
  constructor(@Inject(PRISMA) private readonly prisma: PrismaClientLike) {}

  async recordSignal(organizationId: string, signal: AbuseSignal, context: Record<string, unknown> = {}): Promise<void> {
    if (!(ABUSE_SIGNALS as readonly string[]).includes(signal)) return;
    await (this.prisma as any).abuseSignalRecord.create({
      data: { organizationId, signal, context: context as never },
    }).catch(() => undefined);
  }

  async signalCounts(organizationId: string, windowHours = 24): Promise<Partial<Record<AbuseSignal, number>>> {
    const since = new Date(Date.now() - windowHours * 3600_000);
    const rows = await (this.prisma as any).abuseSignalRecord.findMany({
      where: { organizationId, createdAt: { gte: since } },
    }).catch(() => []);
    const counts: Partial<Record<AbuseSignal, number>> = {};
    for (const row of rows as any[]) counts[row.signal as AbuseSignal] = (counts[row.signal as AbuseSignal] ?? 0) + 1;
    return counts;
  }

  async currentResponse(organizationId: string): Promise<{ response: AbuseResponse; reason: string; counts: Partial<Record<AbuseSignal, number>> }> {
    const counts = await this.signalCounts(organizationId);
    const { response, reason } = evaluateAbuseResponse(counts);
    return { response, reason, counts };
  }

  /** Scan creation is blocked at REQUIRE_REVIEW / BLOCK_SCAN_CREATION (§171). */
  async scanCreationBlocked(organizationId: string): Promise<boolean> {
    const { response } = await this.currentResponse(organizationId);
    return response === "BLOCK_SCAN_CREATION" || response === "REQUIRE_REVIEW";
  }
}
