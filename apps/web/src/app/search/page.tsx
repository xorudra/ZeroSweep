"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Enterprise security search (Prompt 27 §95–§97). Queries run through
 * the governed DSL/text engine — tenant scope and classification
 * ceiling are enforced server-side before retrieval; snippets are
 * escaped; "why matched" shows the exact fields that matched.
 * Try: severity:critical kev:true · technology:wordpress · type:finding
 */
interface SearchResultItem {
  documentId: string; documentType: string; resourceId: string; title: string;
  snippet: string; severity: string | null; riskScore: number | null;
  classification: string; updatedAt: string; whyMatched: string[];
}
interface SearchResponse {
  results: SearchResultItem[]; total: number; nextCursor: string | null;
  facets: Record<string, Array<{ key: string | null; count: number }>>;
  groupCounts: Record<string, number>; interpretedAs: string; dslNote?: string;
  classificationCeiling: string;
}
interface SavedQuery { id: string; name: string; queryText: string; visibility: string }
interface AskResponse { status: string; text: string; dsl?: string; citations: Array<{ documentId: string; title: string }> }

export default function Page() {
  const [query, setQuery] = useState("");
  const [data, setData] = useState<SearchResponse | null>(null);
  const [saved, setSaved] = useState<SavedQuery[]>([]);
  const [suggestions, setSuggestions] = useState<string[]>([]);
  const [ask, setAsk] = useState<AskResponse | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const runSearch = useCallback(async (q: string) => {
    setBusy(true); setError("");
    try {
      setData(await apiFetch<SearchResponse>("/security/search", { method: "POST", body: JSON.stringify({ query: q, group: true }) }));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Search failed.");
    } finally { setBusy(false); }
  }, []);

  const loadSaved = useCallback(async () => {
    try { setSaved(await apiFetch<SavedQuery[]>("/analytics/saved-queries")); } catch { /* saved queries optional */ }
  }, []);

  useEffect(() => { void loadSaved(); }, [loadSaved]);

  useEffect(() => {
    if (query.trim().length < 2) { setSuggestions([]); return; }
    const t = setTimeout(async () => {
      try {
        const out = await apiFetch<{ suggestions: string[] }>(`/security/search/suggestions?q=${encodeURIComponent(query.trim())}`);
        setSuggestions(out.suggestions);
      } catch { setSuggestions([]); }
    }, 250);
    return () => clearTimeout(t);
  }, [query]);

  const saveQuery = async () => {
    if (!query.trim()) return;
    try {
      await apiFetch("/analytics/saved-queries", { method: "POST", body: JSON.stringify({ name: query.trim().slice(0, 60), queryText: query.trim(), visibility: "PRIVATE" }) });
      await loadSaved();
    } catch (e) { setError(e instanceof ApiError ? e.message : "Could not save query."); }
  };

  const askAi = async () => {
    if (!query.trim()) return;
    setBusy(true);
    try {
      setAsk(await apiFetch<AskResponse>("/analytics/ai/ask", { method: "POST", body: JSON.stringify({ question: query.trim() }) }));
    } catch (e) { setError(e instanceof ApiError ? e.message : "AI ask failed."); }
    finally { setBusy(false); }
  };

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Enterprise Search" title="Security Search" body="One governed search across assets, findings, scans, reports, repositories, controls, risks, tickets and audit records — scoped to your tenant and classification ceiling." />
      {error && <p className="rounded bg-red-950/60 px-3 py-2 text-sm text-red-300">{error}</p>}
      <div className="flex flex-wrap gap-2">
        <input
          className="min-w-72 flex-1 rounded border border-slate-700 bg-slate-900 px-3 py-2 text-sm"
          placeholder="Search, or use the DSL — e.g. severity:critical kev:true technology:wordpress"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") void runSearch(query); }}
        />
        <button className="rounded border border-slate-700 px-4 py-2 text-sm disabled:opacity-50" disabled={busy} onClick={() => void runSearch(query)}>Search</button>
        <button className="rounded border border-slate-700 px-4 py-2 text-sm disabled:opacity-50" disabled={busy} onClick={() => void askAi()}>Ask AI</button>
        <button className="rounded border border-slate-700 px-4 py-2 text-sm" onClick={() => void saveQuery()}>Save query</button>
      </div>
      {suggestions.length > 0 && (
        <div className="flex flex-wrap gap-2 text-xs">
          {suggestions.map((s) => (
            <button key={s} className="rounded bg-slate-800 px-2 py-1" onClick={() => { setQuery(s); void runSearch(s); }}>{s}</button>
          ))}
        </div>
      )}
      {saved.length > 0 && (
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="text-slate-400">Saved:</span>
          {saved.map((s) => (
            <button key={s.id} className="rounded bg-slate-800 px-2 py-1" onClick={() => { setQuery(s.queryText); void runSearch(s.queryText); }}>{s.name}</button>
          ))}
        </div>
      )}
      {ask && (
        <Card title={`AI answer (${ask.status})`}>
          <p className="text-sm">{ask.text}</p>
          {ask.dsl && <p className="mt-1 text-xs text-slate-500">Governed DSL: {ask.dsl}</p>}
          {ask.citations.length > 0 && <p className="mt-1 text-xs text-slate-500">Citations: {ask.citations.map((c) => c.title).join(" · ")}</p>}
        </Card>
      )}
      {!data ? (
        <EmptyState title="Search the security lake" body="Results are limited to your workspace and classification ceiling. DSL fields: severity, status, type, asset, technology, cve, cwe, kev, epss, risk, exposure, provider, environment, tag." />
      ) : (
        <>
          <p className="text-sm text-slate-400">
            {data.total} result{data.total === 1 ? "" : "s"} · interpreted as {data.interpretedAs} · classification ceiling {data.classificationCeiling}
            {data.dslNote && <> · <span className="text-amber-300">{data.dslNote}</span></>}
          </p>
          {Object.keys(data.groupCounts).length > 0 && (
            <div className="flex flex-wrap gap-2 text-xs">
              {Object.entries(data.groupCounts).map(([k, v]) => <Badge key={k}>{k}: {v}</Badge>)}
            </div>
          )}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
            <div className="space-y-4">
              {Object.entries(data.facets).map(([facet, rows]) => (
                <Card key={facet} title={facet}>
                  <ul className="space-y-1 text-xs">{rows.slice(0, 8).map((r) => <li key={String(r.key)} className="flex justify-between"><span>{String(r.key)}</span><span>{r.count}</span></li>)}</ul>
                </Card>
              ))}
            </div>
            <div className="space-y-3 lg:col-span-3">
              {data.results.length === 0 ? (
                <EmptyState title="No matches in your scope" body="Nothing in this workspace at your classification ceiling matches. Cross-tenant content is never shown or suggested." />
              ) : data.results.map((r) => (
                <Card key={r.documentId}>
                  <div className="flex flex-wrap items-center gap-2 text-sm">
                    <Badge>{r.documentType}</Badge>
                    {r.severity && <Badge tone={r.severity === "CRITICAL" ? "red" : "amber"}>{r.severity}</Badge>}
                    <span className="font-medium">{r.title}</span>
                    {r.riskScore !== null && <span className="text-slate-500">risk {r.riskScore}</span>}
                  </div>
                  {/* Snippets arrive HTML-escaped from the API (§129). */}
                  <p className="mt-1 text-sm text-slate-300" dangerouslySetInnerHTML={{ __html: r.snippet }} />
                  <p className="mt-1 text-xs text-slate-500">
                    why matched: {r.whyMatched.length ? r.whyMatched.join(", ") : "—"} · {r.classification} · updated {String(r.updatedAt).slice(0, 10)}
                  </p>
                </Card>
              ))}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
