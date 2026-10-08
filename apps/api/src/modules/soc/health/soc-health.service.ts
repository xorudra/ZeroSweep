import { createHash } from "node:crypto";
import { Inject, Injectable } from "@nestjs/common";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireSocPermission } from "../permissions";
import { loadSlaTargets, OPEN_ALERT_STATUSES, type Row } from "../helpers";

/**
 * Telemetry health + data gaps (§115/§116) and SOC SLA evaluation
 * (§90/§91). Evaluation is an explicit operator tick (the same
 * discipline as the P22 scheduler tick — no hidden daemon): it
 * detects silent sources, records gaps, flags SLA risk/breach and
 * emits SOC_SLA_AT_RISK / SOC_SLA_BREACHED into the P27 lake with a
 * deterministic event id, so re-runs never duplicate events.
 */
@Injectable()
export class SocHealthService {
  constructor(@Inject(PRISMA) private readonly prisma: PrismaClientLike) {}

  async telemetryHealth(user: RequestUser, workspaceId: string) {
    requireSocPermission(user, "VIEW_SOC");
    const sources = await this.prisma.socTelemetrySource.findMany({ where: { workspaceId } });
    const gaps = await this.prisma.telemetryDataGap.findMany({ where: { workspaceId, status: "OPEN" } });
    const now = Date.now();
    const items = (sources as Row[]).map((s) => {
      const lastEventAt = s.lastEventAt ? new Date(s.lastEventAt as string) : null;
      const lagSeconds = lastEventAt ? Math.round((now - lastEventAt.getTime()) / 1000) : null;
      const windowStart = new Date(now - 3600 * 1000);
      return {
        sourceId: s.id, name: s.name, sourceCategory: s.sourceCategory, enabled: s.enabled,
        lastEventAt: s.lastEventAt ?? null, eventsIngested: s.eventsIngested ?? 0,
        parseFailures: s.parseFailures ?? 0, authFailures: s.authFailures ?? 0,
        ingestionLagSeconds: lagSeconds,
        expectedIntervalSeconds: s.expectedIntervalSeconds ?? null,
        recentWindowStart: windowStart.toISOString(),
        status: !s.enabled ? "DISABLED" : !lastEventAt ? "NO_DATA_YET" : lagSeconds !== null && s.expectedIntervalSeconds && lagSeconds > (s.expectedIntervalSeconds as number) * 2 ? "GAP" : "REPORTING",
      };
    });
    return { sources: items, openGaps: gaps, evaluatedAt: new Date().toISOString() };
  }

  private async emitLakeEvent(workspaceId: string, organizationId: string, eventId: string, eventType: string, resourceId: string, attributes: Row) {
    const existing = await this.prisma.securityAnalyticsEvent.findFirst({ where: { eventId } });
    if (existing) return false;
    const body = JSON.stringify({ eventId, eventType, resourceId, attributes });
    await this.prisma.securityAnalyticsEvent.create({
      data: {
        eventId, organizationId, workspaceId, eventType, eventTime: new Date(),
        sourceType: "MANUAL_SYNC", resourceType: "ALERT", resourceId,
        severity: eventType.endsWith("BREACHED") ? "HIGH" : "MEDIUM",
        attributes: attributes as never,
        checksum: createHash("sha256").update(body).digest("hex"),
      },
    }).catch(() => undefined);
    return true;
  }

  /** Operator tick: data gaps + SLA evaluation (§91/§116). */
  async evaluate(user: RequestUser, workspaceId: string) {
    requireSocPermission(user, "MANAGE_INCIDENTS");
    const now = new Date();
    let gapsCreated = 0;
    let gapsResolved = 0;
    const sources = await this.prisma.socTelemetrySource.findMany({ where: { workspaceId, enabled: true } });
    for (const source of sources as Row[]) {
      if (!source.expectedIntervalSeconds || !source.lastEventAt) continue;
      const gapSeconds = Math.round((now.getTime() - new Date(source.lastEventAt as string).getTime()) / 1000);
      const openGap = await this.prisma.telemetryDataGap.findFirst({
        where: { workspaceId, sourceId: source.id as string, status: "OPEN" },
      });
      if (gapSeconds > (source.expectedIntervalSeconds as number) * 2) {
        if (!openGap) {
          await this.prisma.telemetryDataGap.create({
            data: {
              workspaceId, sourceId: source.id as string, sourceName: source.name as string,
              lastEventAt: source.lastEventAt as Date, gapSeconds, status: "OPEN",
            },
          });
          gapsCreated++;
        }
      } else if (openGap) {
        await this.prisma.telemetryDataGap.update({
          where: { id: openGap.id as string }, data: { status: "RESOLVED", resolvedAt: now } as never,
        });
        gapsResolved++;
      }
    }

    const targets = await loadSlaTargets(this.prisma, workspaceId);
    let atRisk = 0;
    let breached = 0;
    const alerts = await this.prisma.securityAlert.findMany({
      where: { workspaceId, status: { in: OPEN_ALERT_STATUSES } },
    });
    for (const alert of alerts as Row[]) {
      const target = targets[(alert.priority as keyof typeof targets) ?? "P3"];
      if (!target) continue;
      const ageMinutes = (now.getTime() - new Date(alert.firstSeen as string).getTime()) / 60000;
      if (!alert.acknowledgedAt && ageMinutes > target.triage) {
        if (!alert.slaBreached) {
          await this.prisma.securityAlert.update({ where: { id: alert.id as string }, data: { slaBreached: true } as never });
        }
        if (await this.emitLakeEvent(workspaceId, user.organizationId, `soc-sla:${alert.id}:TRIAGE:BREACHED`, "SOC_SLA_BREACHED", alert.id as string, { priority: alert.priority, ageMinutes: Math.round(ageMinutes), targetMinutes: target.triage })) breached++;
      } else if (!alert.acknowledgedAt && ageMinutes > target.triage * 0.75) {
        if (await this.emitLakeEvent(workspaceId, user.organizationId, `soc-sla:${alert.id}:TRIAGE:AT_RISK`, "SOC_SLA_AT_RISK", alert.id as string, { priority: alert.priority, ageMinutes: Math.round(ageMinutes), targetMinutes: target.triage })) atRisk++;
      }
    }
    void user;
    return { evaluatedAt: now.toISOString(), gapsCreated, gapsResolved, slaAtRisk: atRisk, slaBreached: breached };
  }
}
