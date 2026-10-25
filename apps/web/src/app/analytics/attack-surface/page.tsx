"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState, StatCard } from "@zerosweep/ui";

/**
 * Attack surface intelligence (Prompt 27 §89). Counts come from the
 * live asset/service/technology inventory and exposure snapshots;
 * shadow signals are evidence, never verdicts (§55).
 */
interface KeyCount { key: string | null; count: number }
interface Dashboard {
  sources: string[];
  totalAssets: number; internetFacingAssets: number; unknownAssets: number;
  newAssets: number | null;
  shadowSignals: Array<{ id: string; host: string | null; signalType: string; detectedAt: string; note: string }>;
  services: { open: number; internetExposed: number; byPort: KeyCount[]; byProduct: KeyCount[] };
  technologies: { distribution: KeyCount[]; withVersions: number; onInternetFacingAssets: number };
  certificates: { tlsServices: number; note: string };
}
interface AttackPath { id: string; score: number; status: string; summary?: string | null; nodes: Array<{ kind: string; label: string }> }

export default function Page() {
  const [data, setData] = useState<Dashboard | null>(null);
  const [paths, setPaths] = useState<AttackPath[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");

  const load = useCallback(async () => {
    try {
      setData(await apiFetch<Dashboard>("/analytics/attack-surface"));
      const list = await apiFetch<{ items: AttackPath[] }>("/analytics/attack-paths").catch(() => ({ items: [] }));
      setPaths(list.items);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const run = async (path: string, label: string) => {
    setBusy(true); setNotice("");
    try {
      const out = await apiFetch<Record<string, unknown>>(path, { method: "POST" });
      setNotice(`${label}: ${JSON.stringify(out).slice(0, 240)}`);
      await load();
    } catch (e) {
      setNotice(e instanceof ApiError ? e.message : `${label} failed.`);
    } finally { setBusy(false); }
  };

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Attack Surface Intelligence" title="Attack Surface" body="Internet exposure, services, technologies and certificates from controlled discovery data — plus evidence-backed attack-path candidates for analyst review." />
      {error && <p className="rounded bg-red-950/60 px-3 py-2 text-sm text-red-300">{error}</p>}
      {notice && <p className="rounded bg-slate-800 px-3 py-2 text-sm text-slate-200">{notice}</p>}
      <div className="flex flex-wrap gap-2 text-sm">
        <button className="rounded border border-slate-700 px-3 py-1 disabled:opacity-50" disabled={busy} onClick={() => void run("/analytics/attack-surface/snapshot", "Snapshot captured")}>Capture exposure snapshot</button>
        <button className="rounded border border-slate-700 px-3 py-1 disabled:opacity-50" disabled={busy} onClick={() => void run("/analytics/attack-paths/generate", "Attack paths generated")}>Generate attack paths</button>
      </div>
      {!data ? (
        <EmptyState title="Loading attack surface…" body="" />
      ) : data.totalAssets === 0 ? (
        <EmptyState title="No assets in inventory" body="Attack-surface analytics appear once discovery lands assets in this workspace." />
      ) : (
        <>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <StatCard label="Total assets" value={data.totalAssets} />
            <StatCard label="Internet-facing" value={data.internetFacingAssets} />
            <StatCard label="Unknown / unspecified" value={data.unknownAssets} />
            <StatCard label="Open services" value={data.services.open} hint={`${data.services.internetExposed} internet-exposed`} />
          </div>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <Card title="Top ports">
              <ul className="space-y-1 text-sm">{data.services.byPort.map((r) => <li key={String(r.key)} className="flex justify-between"><span>{r.key ?? "—"}</span><span>{r.count}</span></li>)}</ul>
            </Card>
            <Card title="Technologies">
              <ul className="space-y-1 text-sm">{data.technologies.distribution.map((r) => <li key={String(r.key)} className="flex justify-between"><span>{r.key ?? "—"}</span><span>{r.count}</span></li>)}</ul>
              <p className="mt-2 text-xs text-slate-500">{data.technologies.withVersions} with known versions · {data.technologies.onInternetFacingAssets} on internet-facing assets</p>
            </Card>
            <Card title="Certificates">
              <p className="text-sm">TLS-bearing services: {data.certificates.tlsServices}</p>
              <p className="mt-1 text-xs text-slate-500">{data.certificates.note}</p>
            </Card>
            <Card title="Shadow IT signals (evidence, not verdicts)">
              {data.shadowSignals.length === 0 ? <p className="text-sm text-slate-400">No open signals.</p> : (
                <ul className="space-y-2 text-sm">{data.shadowSignals.map((s) => (
                  <li key={s.id}><Badge>{s.signalType}</Badge> {s.host ?? ""} <span className="text-slate-500">{String(s.detectedAt).slice(0, 10)}</span></li>
                ))}</ul>
              )}
            </Card>
          </div>
          <Card title="Attack-path candidates (analyst review — never exploitation procedures)">
            {paths.length === 0 ? <p className="text-sm text-slate-400">No candidates. Generate after correlations run over internet-facing assets with critical findings.</p> : (
              <ul className="space-y-2 text-sm">{paths.map((p) => (
                <li key={p.id} className="flex flex-wrap items-center gap-2">
                  <Badge tone={p.score >= 70 ? "red" : "amber"}>score {p.score}</Badge>
                  <span>{p.nodes.map((n) => n.label).join(" → ")}</span>
                  <span className="text-slate-500">{p.status}</span>
                </li>
              ))}</ul>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
