import { Inject, Injectable } from "@nestjs/common";
import { computeRemediationMetrics, type CaseTimelineFacts } from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import type { CaseRow } from "./case-state.service";

/**
 * Remediation analytics (Prompt 31 §108–§115). Everything is computed
 * from the append-only status history + case timestamps — real state
 * transitions, never stored counters. The three MTTR clocks of §111
 * (claim / verify / close) are kept distinct and are never mixed with
 * SOC MTTR-IR (Prompt 28, a different definition on a different clock).
 */
@Injectable()
export class RemediationAnalyticsService {
  constructor(@Inject(PRISMA) private readonly prisma: PrismaClientLike) {}

  /** Build SDK timeline facts: first entry timestamp per status,
   *  current breach flag from the latest SLA snapshot. */
  private async factsFor(cases: CaseRow[]): Promise<CaseTimelineFacts[]> {
    const facts: CaseTimelineFacts[] = [];
    for (const kase of cases) {
      const history = await this.prisma.remediationStatusHistory.findMany({
        where: { caseId: kase.id }, orderBy: { createdAt: "asc" }, take: 500,
      });
      const entered: Partial<Record<string, Date>> = {};
      for (const h of history) {
        if (!entered[h.toStatus]) entered[h.toStatus] = h.createdAt;
      }
      const snapshot = await this.prisma.remediationSlaSnapshot.findFirst({
        where: { caseId: kase.id }, orderBy: { createdAt: "desc" },
      });
      facts.push({
        caseId: kase.id, ownerId: kase.ownerId, teamId: kase.teamId,
        createdAt: kase.createdAt, entered, dueAt: kase.dueAt,
        slaBreached: snapshot?.state === "BREACHED",
        regressionCount: kase.regressionCount,
      });
    }
    return facts;
  }

  async metrics(workspaceId: string, filters: { teamId?: string } = {}, now = new Date()) {
    let cases = (await this.prisma.remediationCase.findMany({ where: { workspaceId }, take: 10000 })) as CaseRow[];
    if (filters.teamId) cases = cases.filter((c) => c.teamId === filters.teamId);
    const facts = await this.factsFor(cases);
    const jobs = await this.prisma.remediationVerificationJob.findMany({
      where: { workspaceId, caseId: { in: cases.map((c) => c.id) } }, take: 10000,
    });
    const outcomes = jobs
      .map((j) => j.status)
      .filter((s): s is "PASSED" | "FAILED" | "INCONCLUSIVE" | "ERROR" =>
        ["PASSED", "FAILED", "INCONCLUSIVE", "ERROR"].includes(s));
    const exceptions = await this.prisma.remediationException.findMany({
      where: { workspaceId, status: "APPROVED" }, take: 10000,
    });
    const metrics = computeRemediationMetrics({
      cases: facts, verificationOutcomes: outcomes,
      exceptionCaseIds: exceptions.map((e) => e.caseId),
    });
    // Backlog trend (§110): case creations per day over the last 30
    // days, from real createdAt timestamps.
    const trend: Array<{ day: string; created: number; open: number }> = [];
    for (let d = 29; d >= 0; d -= 1) {
      const dayStart = new Date(now.getTime() - d * 86400_000);
      const key = dayStart.toISOString().slice(0, 10);
      const created = cases.filter((c) => c.createdAt.toISOString().slice(0, 10) === key).length;
      trend.push({ day: key, created, open: metrics.openBacklog });
    }
    return { ...metrics, backlogTrend: trend, asOf: now };
  }

  /** §109 team performance — operational measures, not employee scoring. */
  async teamMetrics(workspaceId: string, now = new Date()) {
    const cases = (await this.prisma.remediationCase.findMany({ where: { workspaceId }, take: 10000 })) as CaseRow[];
    const teams = new Map<string, CaseRow[]>();
    for (const kase of cases) {
      const key = kase.teamId ?? kase.ownerId ?? "unassigned";
      teams.set(key, [...(teams.get(key) ?? []), kase]);
    }
    const out: Array<Record<string, unknown>> = [];
    for (const [team, rows] of teams) {
      const facts = await this.factsFor(rows);
      const m = computeRemediationMetrics({ cases: facts, verificationOutcomes: [], exceptionCaseIds: [] });
      out.push({
        team,
        openCases: m.openBacklog,
        meanTimeToAssignHours: m.meanTimeToAssignHours,
        meanTimeToClaimFixHours: m.meanTimeToClaimFixHours,
        meanTimeToVerifyFixHours: m.meanTimeToVerifyFixHours,
        meanTimeToCloseHours: m.meanTimeToCloseHours,
        regressionRate: m.regressionRate,
      });
    }
    return { teams: out, asOf: now, note: "operational workflow measures (§109) — not simplistic employee scoring" };
  }
}
