"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Card, EmptyState, StatCard } from "@dsrclone/ui";

/**
 * SOC dashboard (Prompt 28 §102). Every number comes from recorded
 * SOC rows — telemetry health, open alert load, SLA risk, detection
 * health. Empty workspace ⇒ empty dashboard; nothing is synthesized.
 */
interface Overview {
  openAlerts: number; p1p2Alerts: number; activeIncidents: number; slaBreached: number;
  indicatorMatches: number; mttaSeconds: number | null; mttcSeconds: number | null; mttrSeconds: number | null;
  falsePositiveRate: number | null; truePositiveRate: number | null;
}
interface SourceHealth {
  sourceId: string; name: string; sourceCategory: string; enabled: boolean; status: string;
  lastEventAt: string | null; eventsIngested: number; ingestionLagSeconds: number | null;
}
interface Dashboard {
  overview: Overview;
  telemetryHealth: { sources: SourceHealth[]; openGaps: unknown[] };
}

function hours(seconds: number | null): string {
  if (seconds === null) return "—";
  return `${(seconds / 3600).toFixed(1)}h`;
}

export default function Page() {
  const [data, setData] = useState<Dashboard | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setData(await apiFetch<Dashboard>("/soc/dashboard"));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const evaluate = async () => {
    setBusy(true);
    try {
      const out = await apiFetch<{ gapsCreated: number; slaAtRisk: number; slaBreached: number }>("/soc/evaluate", { method: "POST", body: JSON.stringify({}) });
      setNotice(`Evaluation complete: ${out.gapsCreated} telemetry gap(s) opened, ${out.slaAtRisk} SLA at-risk, ${out.slaBreached} SLA breached.`);
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Evaluation failed.");
    } finally { setBusy(false); }
  };

  const o = data?.overview;
  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Security Operations" title="Security Operations Center" body="Alerts, incidents, detections and threat intelligence — all derived from recorded platform signals." />
      {error && <p className="text-sm text-red-400">{error}</p>}
      {notice && <p className="text-sm text-emerald-400">{notice}</p>}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard label="Open alerts" value={o ? String(o.openAlerts) : "—"} />
        <StatCard label="Open P1/P2" value={o ? String(o.p1p2Alerts) : "—"} />
        <StatCard label="Active incidents" value={o ? String(o.activeIncidents) : "—"} />
        <StatCard label="SLA breached" value={o ? String(o.slaBreached) : "—"} />
        <StatCard label="Indicator matches" value={o ? String(o.indicatorMatches) : "—"} />
        <StatCard label="MTTA" value={o ? hours(o.mttaSeconds) : "—"} />
        <StatCard label="MTTC" value={o ? hours(o.mttcSeconds) : "—"} />
        <StatCard label="MTTR (incident)" value={o ? hours(o.mttrSeconds) : "—"} />
      </div>
      <div className="flex flex-wrap gap-3">
        <Link className="rounded bg-indigo-600 px-3 py-2 text-sm text-white" href="/soc/alerts">Alert queue</Link>
        <Link className="rounded bg-slate-700 px-3 py-2 text-sm text-white" href="/soc/incidents">Incidents</Link>
        <Link className="rounded bg-slate-700 px-3 py-2 text-sm text-white" href="/soc/detections">Detections</Link>
        <Link className="rounded bg-slate-700 px-3 py-2 text-sm text-white" href="/soc/threat-intelligence">Threat intelligence</Link>
        <Link className="rounded bg-slate-700 px-3 py-2 text-sm text-white" href="/analytics/soc">SOC analytics</Link>
        <button className="rounded bg-slate-800 px-3 py-2 text-sm text-slate-200 disabled:opacity-50" disabled={busy} onClick={evaluate}>
          Run SLA / gap evaluation
        </button>
      </div>
      <Card title="Telemetry source health (§115)">
        {!data || data.telemetryHealth.sources.length === 0 ? (
          <EmptyState title="No telemetry sources registered yet. Sources are registered by SOC leads; ingestion accepts scoped API keys, service accounts or signed webhooks." body="" />
        ) : (
          <ul className="divide-y divide-slate-800">
            {data.telemetryHealth.sources.map((s) => (
              <li key={s.sourceId} className="flex items-center justify-between py-2 text-sm">
                <span>{s.name} <span className="text-slate-500">({s.sourceCategory})</span></span>
                <span className="text-slate-400">
                  {s.status} · {s.eventsIngested} events · last {s.lastEventAt ? new Date(s.lastEventAt).toLocaleString() : "never"}
                </span>
              </li>
            ))}
          </ul>
        )}
        {data && data.telemetryHealth.openGaps.length > 0 && (
          <p className="mt-2 text-sm text-amber-400">{data.telemetryHealth.openGaps.length} open telemetry data gap(s) — a silent source is a detection blind spot (§116).</p>
        )}
      </Card>
    </div>
  );
}
