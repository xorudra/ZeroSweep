"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { Badge, Card, EmptyState } from "@zerosweep/ui";
import { apiFetch, ApiError } from "@/lib/api-client";

interface EpssItem {
  cveId: string; current: number | null; percentile: number | null;
  previous: number | null; change: number | null; freshness: string;
  history: { score: number; date: string }[]; affectedAssets: number;
}
interface EpssDashboard { items: EpssItem[]; movers: EpssItem[]; stale: number; absent: number; note: string }

/** EPSS console (Prompt 30 §100): current values, history, movers, staleness. */
export default function Page() {
  const [data, setData] = useState<EpssDashboard | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    apiFetch<EpssDashboard>("/vulnerability-intelligence/epss").then(setData).catch((e: unknown) => setError(e instanceof ApiError ? e.message : "Could not load the EPSS console."));
  }, []);
  if (error) return <EmptyState title="EPSS console unavailable" body={error} />;
  if (!data) return <p className="text-sm text-slate-400">Loading…</p>;
  return (
    <>
      <PageHeader eyebrow="Vulnerability Intelligence" title="EPSS Console" body={data.note} />
      <div className="grid gap-4 md:grid-cols-3">
        <Card><h3 className="text-sm font-semibold text-slate-200">Material movers</h3><p className="mt-1 text-2xl text-slate-100">{data.movers.length}</p><p className="text-xs text-slate-500">|Δ| ≥ 0.1 between recorded days</p></Card>
        <Card><h3 className="text-sm font-semibold text-slate-200">Stale values</h3><p className="mt-1 text-2xl text-slate-100">{data.stale}</p><p className="text-xs text-slate-500">older than the freshness window — marked, never hidden</p></Card>
        <Card><h3 className="text-sm font-semibold text-slate-200">Absent values</h3><p className="mt-1 text-2xl text-slate-100">{data.absent}</p><p className="text-xs text-slate-500">no EPSS record — shown as absent, never as 0</p></Card>
      </div>
      <Card>
        <h3 className="text-sm font-semibold text-slate-200">Workspace CVEs by EPSS movement</h3>
        {data.items.length === 0 ? <p className="mt-1 text-sm text-slate-500">No CVE-carrying findings in this workspace yet.</p> : (
          <ul className="mt-2 space-y-2 text-sm text-slate-300">
            {data.items.map((i) => (
              <li key={i.cveId}>
                <Link className="text-sky-300 hover:underline" href={`/vulnerabilities/cve/${i.cveId}`}>{i.cveId}</Link>
                {" · "}EPSS {i.current == null ? "absent" : i.current.toFixed(3)}
                {i.percentile != null ? ` (percentile ${i.percentile.toFixed(3)})` : ""}
                {i.change != null ? ` · Δ ${i.change >= 0 ? "+" : ""}${i.change.toFixed(3)}` : ""}
                {" "}<Badge>{i.freshness}</Badge>
                {" · "}{i.affectedAssets} finding(s) · history: {i.history.length ? i.history.map((h) => `${h.date}: ${h.score}`).join(" → ") : "none recorded"}
              </li>
            ))}
          </ul>
        )}
      </Card>
    </>
  );
}
