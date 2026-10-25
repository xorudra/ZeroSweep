"use client";

import { Card } from "@zerosweep/ui";
import { CountTable, DashboardShell, Stat, hours, pct, useAnalytics } from "../DashboardShared";

interface Executive {
  totalOpenFindings: number;
  criticalFindings: number;
  highFindings: number;
  kevFindings: number;
  internetFacingFindings: number;
  productionFindings: number;
  overdueFindings: number;
  resolvedInPeriod: number;
  reopenedInPeriod: number;
  overallRiskScore: number | null;
  mttrHours: number | null;
  reopenRatePct: number | null;
  topRiskyAssets: { asset: string; findings: number; worstSeverity: string }[];
  trends30d: { date: string; newFindings: number; resolvedFindings: number }[];
  coverage: { available: boolean; note: string };
}

/** Executive dashboard (Prompt 20 §71): platform-wide risk posture from
 *  stored canonical findings only. */
export default function ExecutiveDashboardPage() {
  const { data, error } = useAnalytics<Executive>("/analytics/executive");
  return (
    <DashboardShell title="Executive Dashboard" subtitle="Organization risk posture — computed from stored findings, never estimates.">
      {error ? <Card><p className="text-sm text-red-400">{error}</p></Card> : null}
      {!data ? <Card><p className="text-sm text-slate-400">Loading…</p></Card> : (
        <>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <Stat label="Open findings" value={data.totalOpenFindings} />
            <Stat label="Critical" value={data.criticalFindings} />
            <Stat label="KEV-listed" value={data.kevFindings} hint="CISA Known Exploited Vulnerabilities" />
            <Stat label="Internet-facing" value={data.internetFacingFindings} />
            <Stat label="Production" value={data.productionFindings} />
            <Stat label="Overdue SLA" value={data.overdueFindings} />
            <Stat label="Overall risk score" value={data.overallRiskScore ?? "—"} hint="Mean of open finding risk scores" />
            <Stat label="MTTR" value={hours(data.mttrHours)} hint={`Reopen rate ${pct(data.reopenRatePct)}`} />
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <h3 className="mb-2 text-sm font-semibold text-slate-200">Top risky assets</h3>
              {data.topRiskyAssets.length === 0 ? (
                <p className="text-xs text-slate-500">No data in scope — no findings recorded yet.</p>
              ) : (
                <ul className="space-y-1">
                  {data.topRiskyAssets.map((a) => (
                    <li key={a.asset} className="flex items-center justify-between text-sm">
                      <span className="text-slate-300">{a.asset}</span>
                      <span className="text-slate-400">{a.findings} findings · worst {a.worstSeverity}</span>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
            <Card>
              <h3 className="mb-2 text-sm font-semibold text-slate-200">Last 30 days</h3>
              <p className="text-sm text-slate-300">New: {data.trends30d.reduce((n, t) => n + t.newFindings, 0)} · Resolved: {data.trends30d.reduce((n, t) => n + t.resolvedFindings, 0)}</p>
              <p className="mt-2 text-xs text-slate-500">{data.coverage.note}</p>
            </Card>
          </div>
        </>
      )}
    </DashboardShell>
  );
}
