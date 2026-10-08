"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { Badge, Card, EmptyState } from "@dsrclone/ui";
import { apiFetch, ApiError } from "@/lib/api-client";

interface Dashboard {
  activeCveRecords: number;
  kevCatalogActive: number;
  kevAffectingWorkspace: number;
  highEpssFindings: number;
  patchAvailableFindings: number;
  noKnownFixFindings: number;
  topVulnerableComponents: { componentId: string; name: string; confirmedVulnerabilities: number }[];
  blastRadiusLeaders: { cveId: string; confirmedComponents: number }[];
  recentlyChangedIntelligence: { kind: string; cveId: string; at: string }[];
}
interface Providers {
  providers: { provider: string; status: string; freshness: string; detail: string | null }[];
  syncStates: { source: string; status: string; recordCount: number }[];
  liveFetch: { status: string; detail: string };
}
interface Conflict { id: string; cveId: string; conflictType: string; status: string }
interface Answer { answer: string; citations: string[]; executed: boolean }

/**
 * Vulnerability intelligence dashboard (Prompt 30 §98): workspace
 * exposure joined to governed global intelligence. Provider state is
 * shown exactly as recorded — a source that was never synced says so.
 */
export default function Page() {
  const [dashboard, setDashboard] = useState<Dashboard | null>(null);
  const [providers, setProviders] = useState<Providers | null>(null);
  const [conflicts, setConflicts] = useState<Conflict[]>([]);
  const [question, setQuestion] = useState("");
  const [answer, setAnswer] = useState<Answer | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiFetch<Dashboard>("/vulnerability-intelligence/dashboard").then(setDashboard).catch((e: unknown) => setError(e instanceof ApiError ? e.message : "Could not load the intelligence dashboard."));
    apiFetch<Providers>("/vulnerability-intelligence/providers").then(setProviders).catch(() => undefined);
    apiFetch<{ items: Conflict[] }>("/vulnerability-intelligence/conflicts?status=OPEN").then((r) => setConflicts(r.items)).catch(() => undefined);
  }, []);

  const ask = async () => {
    if (!question.trim()) return;
    const res = await apiFetch<Answer>("/vulnerability-intelligence/ask", { method: "POST", body: JSON.stringify({ question }) }).catch(() => null);
    setAnswer(res);
  };

  if (error) return <EmptyState title="Intelligence dashboard unavailable" body={error} />;
  if (!dashboard) return <p className="text-sm text-slate-400">Loading…</p>;

  return (
    <>
      <PageHeader eyebrow="Vulnerability Intelligence" title="Intelligence Dashboard" body="Governed CVE / CVSS / EPSS / KEV / patch intelligence joined to this workspace's exposure. Values come only from recorded feed data with provenance — absent values are shown as absent, never estimated." />
      <div className="grid gap-4 md:grid-cols-3">
        <Card><h3 className="text-sm font-semibold text-slate-200">CVE records</h3><p className="mt-1 text-2xl text-slate-100">{dashboard.activeCveRecords}</p><p className="text-xs text-slate-500">in the governed intelligence dataset</p></Card>
        <Card><h3 className="text-sm font-semibold text-slate-200">KEV exposure</h3><p className="mt-1 text-2xl text-slate-100">{dashboard.kevAffectingWorkspace}</p><p className="text-xs text-slate-500">of {dashboard.kevCatalogActive} catalog entries affect this workspace</p></Card>
        <Card><h3 className="text-sm font-semibold text-slate-200">High-EPSS findings</h3><p className="mt-1 text-2xl text-slate-100">{dashboard.highEpssFindings}</p><p className="text-xs text-slate-500">EPSS ≥ 0.5 · {dashboard.patchAvailableFindings} patchable · {dashboard.noKnownFixFindings} no known fix</p></Card>
      </div>
      <div className="mt-4 grid gap-4 md:grid-cols-2">
        <Card>
          <h3 className="text-sm font-semibold text-slate-200">Top vulnerable components</h3>
          {dashboard.topVulnerableComponents.length === 0 ? <p className="mt-1 text-sm text-slate-500">No confirmed component matches yet — run SBOM correlation from the SBOM explorer.</p> : (
            <ul className="mt-2 space-y-1 text-sm text-slate-300">
              {dashboard.topVulnerableComponents.map((c) => <li key={c.componentId}><Link className="text-sky-300 hover:underline" href={`/software/components/${c.componentId}`}>{c.name}</Link> · {c.confirmedVulnerabilities} confirmed</li>)}
            </ul>
          )}
          <h3 className="mt-4 text-sm font-semibold text-slate-200">Blast-radius leaders</h3>
          <ul className="mt-2 space-y-1 text-sm text-slate-300">
            {dashboard.blastRadiusLeaders.map((b) => <li key={b.cveId}><Link className="text-sky-300 hover:underline" href={`/vulnerabilities/cve/${b.cveId}`}>{b.cveId}</Link> · {b.confirmedComponents} confirmed components</li>)}
          </ul>
        </Card>
        <Card>
          <h3 className="text-sm font-semibold text-slate-200">Recently changed intelligence</h3>
          <ul className="mt-2 space-y-1 text-sm text-slate-300">
            {dashboard.recentlyChangedIntelligence.map((e, i) => <li key={i}><Badge>{e.kind}</Badge> <Link className="text-sky-300 hover:underline" href={`/vulnerabilities/cve/${e.cveId}`}>{e.cveId}</Link> · {e.at.slice(0, 10)}</li>)}
          </ul>
          <h3 className="mt-4 text-sm font-semibold text-slate-200">Open intelligence conflicts</h3>
          {conflicts.length === 0 ? <p className="mt-1 text-sm text-slate-500">No unresolved source conflicts.</p> : (
            <ul className="mt-2 space-y-1 text-sm text-slate-300">
              {conflicts.map((c) => <li key={c.id}><Badge tone="HIGH">{c.conflictType}</Badge> <Link className="text-sky-300 hover:underline" href={`/vulnerabilities/cve/${c.cveId}`}>{c.cveId}</Link></li>)}
            </ul>
          )}
        </Card>
      </div>
      <Card>
        <h3 className="text-sm font-semibold text-slate-200">Intelligence sources</h3>
        {providers ? (
          <>
            <ul className="mt-2 space-y-1 text-sm text-slate-300">
              {providers.syncStates.map((s) => <li key={s.source}>{s.source}: <Badge>{s.status}</Badge> · {s.recordCount} records</li>)}
              {providers.providers.map((p) => <li key={p.provider}>{p.provider}: <Badge>{p.status}</Badge> · freshness {p.freshness}{p.detail ? ` · ${p.detail}` : ""}</li>)}
            </ul>
            <p className="mt-2 text-xs text-slate-500">Live fetch: {providers.liveFetch.status} — {providers.liveFetch.detail}</p>
          </>
        ) : <p className="mt-1 text-sm text-slate-500">Loading source state…</p>}
      </Card>
      <Card>
        <h3 className="text-sm font-semibold text-slate-200">Ask the intelligence copilot</h3>
        <p className="text-xs text-slate-500">Grounded in recorded intelligence only — it cites stored values, says when data is absent, and never executes anything.</p>
        <div className="mt-2 flex gap-2">
          <input className="w-full rounded bg-slate-800 px-3 py-2 text-sm text-slate-100" placeholder="Why is CVE-2021-44228 important? · How do I fix CVE-2023-44487?" value={question} onChange={(e) => setQuestion(e.target.value)} />
          <button className="rounded bg-sky-600 px-4 py-2 text-sm text-white" onClick={ask}>Ask</button>
        </div>
        {answer ? <p className="mt-3 text-sm text-slate-200">{answer.answer}</p> : null}
      </Card>
    </>
  );
}
