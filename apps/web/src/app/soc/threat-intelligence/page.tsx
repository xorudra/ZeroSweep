"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@zerosweep/ui";

/**
 * Threat intelligence (Prompt 28 §67). Indicators carry source,
 * confidence and expiry — an expired or low-confidence indicator is
 * shown as exactly that, never silently treated as fact (§63/§66).
 * Live feed transports are not wired in this environment: sync
 * reports NOT_CONFIGURED honestly; recorded fixture imports are the
 * ingestion path. Internal data is never submitted to external
 * providers (§68) — there is no outbound lookup here.
 */
interface Source { id: string; name: string; type: string; trustLevel: number; transportStatus: string; enabled: boolean }
interface Indicator {
  id: string; type: string; valueNormalized: string; confidence: number; status: string;
  severity: string; lastSeen: string; validUntil?: string | null;
  provenance?: { sources: string[]; observationCount: number };
}
interface Match { id: string; indicatorId: string; confidence: number; matchedAt: string; context: Record<string, unknown> }

export default function Page() {
  const [sources, setSources] = useState<Source[]>([]);
  const [indicators, setIndicators] = useState<Indicator[]>([]);
  const [matches, setMatches] = useState<Match[]>([]);
  const [q, setQ] = useState("");
  const [sourceName, setSourceName] = useState("");
  const [trustLevel, setTrustLevel] = useState(70);
  const [importSourceId, setImportSourceId] = useState("");
  const [bundle, setBundle] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const load = useCallback(async () => {
    try {
      const out = await apiFetch<{ sources: { items: Source[] }; indicators: { items: Indicator[] }; recentMatches: { items: Match[] } }>(
        `/soc/threat-intelligence${q ? `?q=${encodeURIComponent(q)}` : ""}`);
      setSources(out.sources.items);
      setIndicators(out.indicators.items);
      setMatches(out.recentMatches.items);
      if (!importSourceId && out.sources.items.length > 0) setImportSourceId(out.sources.items[0]!.id);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, [q, importSourceId]);

  useEffect(() => { void load(); }, [load]);

  const call = async (fn: () => Promise<unknown>, ok: string) => {
    try { await fn(); setNotice(ok); await load(); }
    catch (e) { setError(e instanceof ApiError ? e.message : "Action failed."); }
  };

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Threat Intelligence" title="Threat Intelligence" body="Workspace indicators with provenance, deterministic confidence and expiry. Matches enrich events — they never assert attribution." />
      {error && <p className="text-sm text-red-400">{error}</p>}
      {notice && <p className="text-sm text-emerald-400">{notice}</p>}
      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Feed sources (§55)">
          <div className="space-y-2">
            <div className="flex gap-2">
              <input className="flex-1 rounded bg-slate-800 px-2 py-1 text-sm" placeholder="Source name" value={sourceName} onChange={(e) => setSourceName(e.target.value)} />
              <input className="w-20 rounded bg-slate-800 px-2 py-1 text-sm" type="number" min={0} max={100} value={trustLevel} onChange={(e) => setTrustLevel(Number(e.target.value))} />
              <button className="rounded bg-indigo-600 px-3 py-1 text-sm text-white"
                onClick={() => call(() => apiFetch("/soc/intel-sources", { method: "POST", body: JSON.stringify({ name: sourceName, type: "FIXTURE", trustLevel }) }), "Source registered (transport NOT_CONFIGURED until a feed connector is wired).")}>
                Register fixture source
              </button>
            </div>
            {sources.length === 0 ? <EmptyState title="No intel sources registered." body="" /> : (
              <ul className="divide-y divide-slate-800 text-sm">
                {sources.map((s) => (
                  <li key={s.id} className="flex items-center justify-between py-2">
                    <span>{s.name} <span className="text-slate-500">trust {s.trustLevel}</span></span>
                    <span className="flex items-center gap-2">
                      <Badge>{s.transportStatus}</Badge>
                      <button className="rounded bg-slate-700 px-2 py-1 text-xs text-white"
                        onClick={() => call(() => apiFetch(`/soc/intel-sources/${s.id}/sync`, { method: "POST", body: JSON.stringify({}) }), "Sync recorded as NOT_CONFIGURED — no feed data was fabricated.")}>Sync</button>
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </Card>
        <Card title="Import recorded STIX bundle (§60 — validated, size-capped, never evaluated)">
          <div className="space-y-2">
            <select className="w-full rounded bg-slate-800 px-2 py-1 text-sm" value={importSourceId} onChange={(e) => setImportSourceId(e.target.value)}>
              {sources.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
            </select>
            <textarea className="w-full rounded bg-slate-800 px-2 py-1 font-mono text-xs" rows={6} placeholder={"{\"type\":\"bundle\",\"objects\":[{\"type\":\"indicator\",\"pattern\":\"[domain-name:value = 'evil.example']\"}]}"} value={bundle} onChange={(e) => setBundle(e.target.value)} />
            <button className="rounded bg-indigo-600 px-3 py-1 text-sm text-white" disabled={!importSourceId}
              onClick={() => call(async () => {
                const out = await apiFetch<{ created: number; updated: number; parseErrors: string[] }>(`/soc/intel-sources/${importSourceId}/import`, { method: "POST", body: JSON.stringify({ format: "STIX", bundle: JSON.parse(bundle) }) });
                setNotice(`Import complete: ${out.created} created, ${out.updated} updated, ${out.parseErrors.length} parse error(s).`);
              }, "Import complete.")}>
              Import bundle
            </button>
          </div>
        </Card>
      </div>
      <Card title={`Indicators (${indicators.length})`}>
        <input className="mb-3 w-full rounded bg-slate-800 px-2 py-1 text-sm" placeholder="Search indicator values…" value={q} onChange={(e) => setQ(e.target.value)} />
        {indicators.length === 0 ? <EmptyState title="No indicators stored. Import a recorded fixture bundle to populate the store." body="" /> : (
          <ul className="divide-y divide-slate-800 text-sm">
            {indicators.map((i) => (
              <li key={i.id} className="py-2">
                <span className="text-slate-100">{i.type}: {i.valueNormalized}</span>
                <div className="mt-1 flex flex-wrap gap-2 text-xs text-slate-400">
                  <Badge>{i.status}</Badge><Badge>confidence {i.confidence}</Badge><Badge>{i.severity}</Badge>
                  <span>last seen {new Date(i.lastSeen).toLocaleString()}</span>
                  {i.validUntil && <span>valid until {new Date(i.validUntil).toLocaleString()}</span>}
                  {i.provenance && <span>from: {i.provenance.sources.join(", ") || "—"} ({i.provenance.observationCount} observation(s))</span>}
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>
      <Card title="Recent indicator matches (§64)">
        {matches.length === 0 ? <EmptyState title="No matches yet. Matches are recorded when ingested telemetry touches a stored indicator value." body="" /> : (
          <ul className="divide-y divide-slate-800 text-sm">
            {matches.map((m) => (
              <li key={m.id} className="py-2 text-slate-300">
                indicator {m.indicatorId} · confidence {m.confidence} · {new Date(m.matchedAt).toLocaleString()}
                <span className="block text-xs text-slate-500">
                  detection active: {String(m.context.detectionActive)} · provenance: {Array.isArray(m.context.provenance) ? (m.context.provenance as string[]).join(", ") : "—"}
                </span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
