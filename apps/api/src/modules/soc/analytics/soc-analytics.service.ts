import { Inject, Injectable } from "@nestjs/common";
import { meanSeconds } from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireSocPermission } from "../permissions";
import { OPEN_ALERT_STATUSES, type Row } from "../helpers";

/**
 * SOC analytics (Prompt 28 §122/§123) — computed ONLY from recorded
 * SOC rows. Empty workspace ⇒ empty metrics (nulls, not zeroes
 * dressed as data). Metric definitions (§123):
 *  - MTTA: alert created → first triage (acknowledgement proxy).
 *  - MTTC: incident declared → contained.
 *  - MTTR-IR: incident declared → recovered/closed. This is INCIDENT
 *    response MTTR — never mixed with vulnerability-remediation MTTR.
 */
@Injectable()
export class SocAnalyticsService {
  constructor(@Inject(PRISMA) private readonly prisma: PrismaClientLike) {}

  async overview(user: RequestUser, workspaceId: string) {
    requireSocPermission(user, "VIEW_SOC");
    const [alerts, incidents, matches, rules] = await Promise.all([
      this.prisma.securityAlert.findMany({ where: { workspaceId } }),
      this.prisma.securityIncident.findMany({ where: { workspaceId } }),
      this.prisma.indicatorMatch.findMany({ where: { workspaceId } }),
      this.prisma.detectionRule.findMany({ where: { workspaceId } }),
    ]);
    const alertRows = alerts as Row[];
    const incidentRows = incidents as Row[];
    const seconds = (a: unknown, b: unknown): number | null => {
      if (!a || !b) return null;
      return (new Date(b as string).getTime() - new Date(a as string).getTime()) / 1000;
    };
    const mtta = meanSeconds(alertRows.map((a) => seconds(a.firstSeen, a.acknowledgedAt)).filter((v): v is number => v !== null && v >= 0));
    const mttc = meanSeconds(incidentRows.map((i) => seconds(i.declaredAt, i.containedAt)).filter((v): v is number => v !== null && v >= 0));
    const mttr = meanSeconds(incidentRows.map((i) => seconds(i.declaredAt, i.recoveredAt ?? i.closedAt)).filter((v): v is number => v !== null && v >= 0));

    // Triage outcomes per rule → TP/FP rates (§38/§122).
    const triage = await this.prisma.alertTriage.findMany({ where: { workspaceId } });
    const alertById = new Map(alertRows.map((a) => [a.id as string, a]));
    let tp = 0; let fp = 0;
    for (const t of triage as Row[]) {
      if (t.decision === "TRUE_POSITIVE") tp++;
      if (t.decision === "FALSE_POSITIVE") fp++;
    }
    const decided = tp + fp;
    const ruleStats = (rules as Row[]).map((r) => ({
      ruleId: r.id, name: r.name, matchCount: r.matchCount ?? 0,
      alerts: alertRows.filter((a) => a.ruleId === r.id).length,
    })).sort((a, b) => b.alerts - a.alerts).slice(0, 10);
    const byDay = new Map<string, number>();
    for (const a of alertRows) {
      const day = new Date(a.firstSeen as string).toISOString().slice(0, 10);
      byDay.set(day, (byDay.get(day) ?? 0) + 1);
    }
    return {
      sources: ["SecurityAlert", "AlertTriage", "SecurityIncident", "IndicatorMatch", "DetectionRule"],
      metricDefinitions: {
        MTTA: "alert created → first triage (seconds, mean)",
        MTTC: "incident declared → contained (seconds, mean)",
        MTTR: "incident declared → recovered/closed (seconds, mean) — incident-response MTTR, distinct from vulnerability-remediation MTTR (§123)",
      },
      openAlerts: alertRows.filter((a) => OPEN_ALERT_STATUSES.includes(a.status as string)).length,
      p1p2Alerts: alertRows.filter((a) => ["P1", "P2"].includes(a.priority as string) && OPEN_ALERT_STATUSES.includes(a.status as string)).length,
      activeIncidents: incidentRows.filter((i) => i.status !== "CLOSED").length,
      slaBreached: alertRows.filter((a) => a.slaBreached).length,
      indicatorMatches: (matches as Row[]).length,
      alertsOverTime: [...byDay.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([day, count]) => ({ day, count })),
      truePositiveRate: decided > 0 ? Math.round((tp / decided) * 1000) / 1000 : null,
      falsePositiveRate: decided > 0 ? Math.round((fp / decided) * 1000) / 1000 : null,
      mttaSeconds: mtta, mttcSeconds: mttc, mttrSeconds: mttr,
      incidentCount: incidentRows.length,
      topRules: ruleStats,
      topAssets: this.topCounts(alertRows.map((a) => a.assetId as string | undefined)),
      topIdentities: this.topCounts(alertRows.map((a) => a.identityReference as string | undefined)),
    };
  }

  private topCounts(values: Array<string | undefined>): Array<{ key: string; count: number }> {
    const counts = new Map<string, number>();
    for (const v of values) if (v) counts.set(v, (counts.get(v) ?? 0) + 1);
    return [...counts.entries()].map(([key, count]) => ({ key, count })).sort((a, b) => b.count - a.count).slice(0, 10);
  }
}
