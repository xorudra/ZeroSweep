"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Card, EmptyState, StatCard } from "@zerosweep/ui";

/**
 * SOC analytics (Prompt 28 §122/§123). Computed only from recorded
 * SOC rows — an empty workspace shows empty metrics (nulls), never
 * synthesized numbers. MTTR here is INCIDENT-response MTTR and is
 * never mixed with vulnerability-remediation MTTR (§123).
 */
interface Overview {
  sources: string[]; metricDefinitions: Record<string, string>;
  openAlerts: number; p1p2Alerts: number; activeIncidents: number; slaBreached: number;
  indicatorMatches: number; incidentCount: number;
  alertsOverTime: Array<{ day: string; count: number }>;
  truePositiveRate: number | null; falsePositiveRate: number | null;
  mttaSeconds: number | null; mttcSeconds: number | null; mttrSeconds: number | null;
  topRules: Array<{ ruleId: string; name: string; alerts: number }>;
  topAssets: Array<{ key: string; count: number }>;
  topIdentities: Array<{ key: string; count: number }>;
}

function hours(seconds: number | null): string {
  if (seconds === null) return "—";
  return `${(seconds / 3600).toFixed(1)}h`;
}
function pct(v: number | null): string {
  return v === null ? "—" : `${Math.round(v * 100)}%`;
}

export default function Page() {
  const [data, setData] = useState<Overview | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      setData(await apiFetch<Overview>("/soc/analytics"));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="SOC Analytics" title="SOC Analytics" body="Operational metrics over recorded alerts, triage decisions and incidents only." />
      {error && <p className="text-sm text-red-400">{error}</p>}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard label="MTTA (alert → triage)" value={data ? hours(data.mttaSeconds) : "—"} />
        <StatCard label="MTTC (declared → contained)" value={data ? hours(data.mttcSeconds) : "—"} />
        <StatCard label="MTTR (incident response)" value={data ? hours(data.mttrSeconds) : "—"} />
        <StatCard label="False-positive rate" value={data ? pct(data.falsePositiveRate) : "—"} />
        <StatCard label="True-positive rate" value={data ? pct(data.truePositiveRate) : "—"} />
        <StatCard label="Open alerts" value={data ? String(data.openAlerts) : "—"} />
        <StatCard label="Incidents (total)" value={data ? String(data.incidentCount) : "—"} />
        <StatCard label="SLA breached" value={data ? String(data.slaBreached) : "—"} />
      </div>
      {data && (
        <p className="text-xs text-slate-500">
          Definitions — MTTA: {data.metricDefinitions.MTTA}; MTTC: {data.metricDefinitions.MTTC}; MTTR: {data.metricDefinitions.MTTR}.
          Sources: {data.sources.join(", ")}.
        </p>
      )}
      <div className="grid gap-6 lg:grid-cols-3">
        <Card title="Alerts over time">
          {!data || data.alertsOverTime.length === 0 ? <EmptyState title="No alerts recorded yet." body="" /> : (
            <ul className="text-sm text-slate-300">
              {data.alertsOverTime.map((d) => <li key={d.day} className="flex justify-between py-1"><span>{d.day}</span><span>{d.count}</span></li>)}
            </ul>
          )}
        </Card>
        <Card title="Top detection rules">
          {!data || data.topRules.length === 0 ? <EmptyState title="No rules have produced alerts yet." body="" /> : (
            <ul className="text-sm text-slate-300">
              {data.topRules.map((r) => <li key={r.ruleId} className="flex justify-between py-1"><span>{r.name}</span><span>{r.alerts}</span></li>)}
            </ul>
          )}
        </Card>
        <Card title="Top assets / identities">
          {!data || (data.topAssets.length === 0 && data.topIdentities.length === 0) ? <EmptyState title="No alert subjects recorded yet." body="" /> : (
            <ul className="text-sm text-slate-300">
              {data.topAssets.map((a) => <li key={`a-${a.key}`} className="flex justify-between py-1"><span>asset {a.key}</span><span>{a.count}</span></li>)}
              {data.topIdentities.map((a) => <li key={`i-${a.key}`} className="flex justify-between py-1"><span>identity {a.key}</span><span>{a.count}</span></li>)}
            </ul>
          )}
        </Card>
      </div>
    </div>
  );
}
