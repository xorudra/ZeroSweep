"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Card, EmptyState, StatCard } from "@zerosweep/ui";

/**
 * Security analytics overview (Prompt 27 §88). Every number is
 * computed from landed platform records (sources named on the
 * response); empty workspaces render empty — nothing is synthesized.
 */
interface Overview {
  sources: string[];
  criticalExposure: number;
  kevExposure: number;
  mttr: { meanSeconds: number | null; medianSeconds: number | null; resolvedCount: number };
  regressionRate: number | null;
  regressions: number;
  findingTrend: Array<{ bucketStart: string; count: number }>;
  findingTrendDelta: { current: number; previous: number; deltaPct: number | null };
  attackSurfaceGrowth: { netGrowth: number | null; note?: string } | null;
  securityGatePerformance: { total: number; passed: number; failed: number; passRate: number | null };
}
interface Health {
  status: string; events: number; documents: number; deadLetterCount: number;
  ingestionLagSeconds: number | null; alerts: string[];
}

function hours(seconds: number | null): string {
  if (seconds === null) return "—";
  return `${(seconds / 3600).toFixed(1)}h`;
}

export default function Page() {
  const [data, setData] = useState<Overview | null>(null);
  const [health, setHealth] = useState<Health | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState("");
  const [notice, setNotice] = useState("");

  const load = useCallback(async () => {
    try {
      setData(await apiFetch<Overview>("/analytics/overview"));
      setHealth(await apiFetch<Health>("/analytics/health"));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const act = async (label: string, path: string) => {
    setBusy(label); setNotice("");
    try {
      const out = await apiFetch<Record<string, unknown>>(path, { method: "POST" });
      setNotice(`${label} complete: ${JSON.stringify(out).slice(0, 300)}`);
      await load();
    } catch (e) {
      setNotice(e instanceof ApiError ? e.message : `${label} failed.`);
    } finally { setBusy(""); }
  };

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Security Data Lake" title="Analytics" body="Trends, exposure, MTTR and regression analytics computed from the security data lake — every figure traces to the named source tables." />
      {error && <p className="rounded bg-red-950/60 px-3 py-2 text-sm text-red-300">{error}</p>}
      {notice && <p className="rounded bg-slate-800 px-3 py-2 text-sm text-slate-200">{notice}</p>}
      <nav className="flex flex-wrap gap-2 text-sm">
        <Link className="rounded border border-slate-700 px-3 py-1" href="/analytics/attack-surface">Attack Surface</Link>
        <Link className="rounded border border-slate-700 px-3 py-1" href="/analytics/vulnerabilities">Vulnerabilities</Link>
        <Link className="rounded border border-slate-700 px-3 py-1" href="/analytics/devsecops">DevSecOps</Link>
        <Link className="rounded border border-slate-700 px-3 py-1" href="/analytics/cloud">Cloud</Link>
        <Link className="rounded border border-slate-700 px-3 py-1" href="/analytics/identity">Identity</Link>
        <Link className="rounded border border-slate-700 px-3 py-1" href="/analytics/grc">GRC Analytics</Link>
        <Link className="rounded border border-slate-700 px-3 py-1" href="/search">Security Search</Link>
      </nav>
      <div className="flex flex-wrap gap-2 text-sm">
        <button className="rounded border border-slate-700 px-3 py-1 disabled:opacity-50" disabled={!!busy} onClick={() => void act("Ingestion run", "/analytics/ingestion/run")}>{busy === "Ingestion run" ? "Running…" : "Run ingestion"}</button>
        <button className="rounded border border-slate-700 px-3 py-1 disabled:opacity-50" disabled={!!busy} onClick={() => void act("Index rebuild", "/analytics/index")}>{busy === "Index rebuild" ? "Running…" : "Rebuild search index"}</button>
        <button className="rounded border border-slate-700 px-3 py-1 disabled:opacity-50" disabled={!!busy} onClick={() => void act("Correlation run", "/analytics/correlations/run")}>{busy === "Correlation run" ? "Running…" : "Run correlations"}</button>
        <button className="rounded border border-slate-700 px-3 py-1 disabled:opacity-50" disabled={!!busy} onClick={() => void act("Projection rebuild", "/analytics/projections/rebuild")}>{busy === "Projection rebuild" ? "Running…" : "Rebuild projections"}</button>
      </div>
      {!data ? (
        <EmptyState title="Loading analytics…" body="" />
      ) : (
        <>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <StatCard label="Critical exposure (open)" value={data.criticalExposure} />
            <StatCard label="KEV exposure (open)" value={data.kevExposure} />
            <StatCard label="Mean time to remediate" value={hours(data.mttr.meanSeconds)} hint={`${data.mttr.resolvedCount} resolved findings`} />
            <StatCard label="Regression rate" value={data.regressionRate === null ? "—" : `${(data.regressionRate * 100).toFixed(1)}%`} hint={`${data.regressions} regressions`} />
          </div>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <Card title="Finding creation trend (from landed events)">
              {data.findingTrend.every((p) => p.count === 0) ? (
                <p className="text-sm text-slate-400">No finding events landed yet. Run ingestion after scans complete — trends appear from real events only.</p>
              ) : (
                <ul className="space-y-1 text-sm">
                  {data.findingTrend.slice(-14).map((p) => (
                    <li key={p.bucketStart} className="flex justify-between"><span>{String(p.bucketStart).slice(0, 10)}</span><span>{p.count}</span></li>
                  ))}
                </ul>
              )}
              <p className="mt-2 text-xs text-slate-500">Period delta: {data.findingTrendDelta.deltaPct === null ? "not computable (no previous period data)" : `${data.findingTrendDelta.deltaPct.toFixed(1)}%`}</p>
            </Card>
            <Card title="Lake health">
              {health ? (
                <ul className="space-y-1 text-sm">
                  <li>Status: {health.status}</li>
                  <li>Landed events: {health.events} · Search documents: {health.documents}</li>
                  <li>Dead-letter (quarantined) events: {health.deadLetterCount}</li>
                  <li>Ingestion lag: {health.ingestionLagSeconds === null ? "—" : `${health.ingestionLagSeconds}s`}</li>
                  {health.alerts.length > 0 && <li className="text-amber-300">Alerts: {health.alerts.join(", ")}</li>}
                </ul>
              ) : <p className="text-sm text-slate-400">Health unavailable.</p>}
              <p className="mt-2 text-xs text-slate-500">Sources: {data.sources.join(", ")}</p>
            </Card>
          </div>
        </>
      )}
    </div>
  );
}
