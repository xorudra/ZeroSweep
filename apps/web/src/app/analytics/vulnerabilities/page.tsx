"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Card, EmptyState, StatCard } from "@zerosweep/ui";

/**
 * Vulnerability analytics (Prompt 27 §90): severity/CWE/CVE
 * distributions, KEV/EPSS, MTTR, SLA posture and regression ranking —
 * all computed from Finding rows and lifecycle projections.
 */
interface KeyCount { key: string | null; count: number }
interface MttrRow { key: string | null; resolvedCount: number; unresolvedCount: number; meanSeconds: number | null; medianSeconds: number | null }
interface VulnAnalytics {
  sources: string[]; total: number;
  severityDistribution: KeyCount[]; statusDistribution: KeyCount[];
  topCves: KeyCount[]; topCwes: KeyCount[];
  kev: { listed: number; open: number; overdue: number };
  epss: { p50: number | null; p95: number | null; tracked: number };
  mttrBySeverity: MttrRow[];
  sla: Record<string, number>;
  regressionRanking: Array<{ findingId: string; regressionCount: number; severity: string | null }>;
}

function hours(seconds: number | null): string {
  if (seconds === null) return "—";
  return `${(seconds / 3600).toFixed(1)}h`;
}

export default function Page() {
  const [data, setData] = useState<VulnAnalytics | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      setData(await apiFetch<VulnAnalytics>("/analytics/findings"));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Vulnerability Analytics" title="Vulnerabilities" body="Distributions, MTTR, SLA posture and regressions from real findings and their lifecycle projections. Unresolved findings never enter MTTR means." />
      {error && <p className="rounded bg-red-950/60 px-3 py-2 text-sm text-red-300">{error}</p>}
      {!data ? (
        <EmptyState title="Loading vulnerability analytics…" body="" />
      ) : data.total === 0 ? (
        <EmptyState title="No findings yet" body="Analytics populate from real scan findings in this workspace." />
      ) : (
        <>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <StatCard label="Total findings" value={data.total} />
            <StatCard label="KEV listed" value={data.kev.listed} hint={`${data.kev.open} open · ${data.kev.overdue} overdue`} />
            <StatCard label="EPSS p95" value={data.epss.p95 === null ? "—" : data.epss.p95.toFixed(3)} hint={`${data.epss.tracked} tracked`} />
            <StatCard label="SLA breached" value={data.sla.BREACHED ?? 0} hint={`${data.sla.OVERDUE ?? 0} overdue`} />
          </div>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <Card title="By severity">
              <ul className="space-y-1 text-sm">{data.severityDistribution.map((r) => <li key={String(r.key)} className="flex justify-between"><span>{r.key}</span><span>{r.count}</span></li>)}</ul>
            </Card>
            <Card title="By lifecycle status">
              <ul className="space-y-1 text-sm">{data.statusDistribution.map((r) => <li key={String(r.key)} className="flex justify-between"><span>{r.key}</span><span>{r.count}</span></li>)}</ul>
            </Card>
            <Card title="Top CWEs">
              <ul className="space-y-1 text-sm">{data.topCwes.map((r) => <li key={String(r.key)} className="flex justify-between"><span>{r.key}</span><span>{r.count}</span></li>)}</ul>
            </Card>
            <Card title="Top CVEs">
              <ul className="space-y-1 text-sm">{data.topCves.map((r) => <li key={String(r.key)} className="flex justify-between"><span>{r.key}</span><span>{r.count}</span></li>)}</ul>
            </Card>
            <Card title="MTTR by severity">
              {data.mttrBySeverity.length === 0 ? <p className="text-sm text-slate-400">No resolved findings yet — MTTR appears after the first resolution.</p> : (
                <ul className="space-y-1 text-sm">{data.mttrBySeverity.map((r) => <li key={String(r.key)} className="flex justify-between"><span>{r.key}</span><span>mean {hours(r.meanSeconds)} · median {hours(r.medianSeconds)} · n={r.resolvedCount}</span></li>)}</ul>
              )}
            </Card>
            <Card title="Regression ranking">
              {data.regressionRanking.length === 0 ? <p className="text-sm text-slate-400">No regressions recorded.</p> : (
                <ul className="space-y-1 text-sm">{data.regressionRanking.map((r) => <li key={r.findingId} className="flex justify-between"><span>{r.findingId} ({r.severity ?? "—"})</span><span>{r.regressionCount} regressions</span></li>)}</ul>
              )}
            </Card>
          </div>
          <p className="text-xs text-slate-500">Sources: {data.sources.join(", ")}</p>
        </>
      )}
    </div>
  );
}
