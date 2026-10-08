"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { Badge, Card, EmptyState } from "@dsrclone/ui";
import { apiFetch } from "@/lib/api-client";

interface ProviderHealth { provider: string; type: string; status: string; latencyMs: number | null }
interface DashboardData {
  providers: ProviderHealth[];
  recentAnalyses: { id: string; task: string; status: string; modelName?: string; createdAt: string }[];
  feedbackByRating: Record<string, number>;
  observability: { requests: number; totalTokens: number; redactions: number; promptInjectionDetections: number; byStatus: Record<string, number> };
}
interface QueryResult { id: string; title: string; severity: string; cve?: string | null; riskScore?: number | null }

/**
 * AI dashboard (Prompt 21 §108) + natural-language search bar (§113).
 * Search runs the governed typed DSL over this workspace's findings —
 * never raw SQL (§42/§95). Provider health shows status only, never
 * credentials (§110).
 */
export default function AiDashboardPage() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [question, setQuestion] = useState("");
  const [results, setResults] = useState<QueryResult[] | null>(null);
  const [queryError, setQueryError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => { apiFetch<DashboardData>("/ai/dashboard").then(setData).catch((e: Error) => setError(e.message)); }, []);

  const search = async () => {
    setBusy(true); setQueryError(null);
    try {
      const res = await apiFetch<{ results: QueryResult[] }>("/ai/query", { method: "POST", body: JSON.stringify({ question }) });
      setResults(res.results);
    } catch (e) { setQueryError((e as Error).message); setResults(null); }
    finally { setBusy(false); }
  };

  return (
    <>
      <PageHeader eyebrow="AI Security Copilot" title="AI dashboard"
        body="Analyst assistant over normalized platform data. It explains, summarizes and drafts — it cannot run scans, commands or SQL. Answers cite the records they are grounded in." />
      {error && <p className="mb-4 text-sm text-rose-300">{error}</p>}

      <Card title="Ask the security data (§113)" eyebrow="Natural-language search">
        <div className="flex gap-2">
          <input value={question} onChange={(e) => setQuestion(e.target.value)}
            placeholder="Show verified critical production findings / Which assets have KEV vulnerabilities? / Show overdue mobile findings"
            className="flex-1 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-100" />
          <button disabled={busy || question.trim().length < 3} onClick={() => void search()}
            className="rounded-lg bg-cyan-500/10 px-4 py-2 text-sm font-medium text-cyan-300 hover:bg-cyan-500/20 disabled:opacity-50">
            {busy ? "Searching…" : "Search"}
          </button>
        </div>
        {queryError && <p className="mt-2 text-sm text-rose-300">{queryError}</p>}
        {results !== null && (results.length === 0
          ? <p className="mt-3 text-sm text-slate-400">No findings match that governed query in this workspace.</p>
          : <ul className="mt-3 space-y-1 text-sm">
              {results.map((r) => (
                <li key={r.id} className="flex items-center gap-2">
                  <Badge tone={r.severity}>{r.severity}</Badge>
                  <Link href={`/findings/${r.id}`} className="text-sky-300 hover:underline">{r.title}</Link>
                  {r.cve && <span className="text-slate-400">{r.cve}</span>}
                </li>
              ))}
            </ul>)}
        <p className="mt-3 text-sm"><Link href="/ai/copilot" className="text-sky-300 hover:underline">Open the workspace Copilot chat →</Link></p>
      </Card>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <Card title="Provider health (§110)" eyebrow="Providers">
          {!data ? <p className="text-sm text-slate-400">Loading…</p>
            : data.providers.length === 0
              ? <EmptyState title="No AI provider configured" body="The copilot runs in NOT_CONFIGURED mode: deterministic rule-based summaries only, never presented as AI output. Configure a provider under Settings → AI." />
              : <ul className="space-y-2 text-sm">
                  {data.providers.map((p) => (
                    <li key={p.provider} className="flex items-center justify-between">
                      <span>{p.provider} <span className="text-slate-500">({p.type})</span></span>
                      <Badge tone={p.status === "HEALTHY" ? "success" : "warning"}>{p.status}</Badge>
                    </li>
                  ))}
                </ul>}
        </Card>
        <Card title="Observability (§118)" eyebrow="Usage">
          {!data ? <p className="text-sm text-slate-400">Loading…</p> : (
            <ul className="space-y-1 text-sm text-slate-300">
              <li>Requests: {data.observability.requests}</li>
              <li>Total tokens: {data.observability.totalTokens}</li>
              <li>Context redactions: {data.observability.redactions}</li>
              <li>Prompt-injection detections: {data.observability.promptInjectionDetections}</li>
              <li>By status: {Object.entries(data.observability.byStatus).map(([k, v]) => `${k} ${v}`).join(" · ") || "—"}</li>
              <li>Feedback: {Object.entries(data.feedbackByRating).map(([k, v]) => `${k} ${v}`).join(" · ") || "none yet"}</li>
            </ul>
          )}
        </Card>
      </div>

      <div className="mt-4">
        <Card title="Recent analyses" eyebrow="Copilot">
          {!data ? <p className="text-sm text-slate-400">Loading…</p>
            : data.recentAnalyses.length === 0
              ? <EmptyState title="No copilot activity yet" body="Explain a finding, run a natural-language search, or open the Copilot chat to start." />
              : <ul className="space-y-1 text-sm">
                  {data.recentAnalyses.map((r) => (
                    <li key={r.id} className="flex items-center gap-2">
                      <Badge tone="neutral">{r.task}</Badge>
                      <Badge tone={r.status === "COMPLETED" ? "success" : "warning"}>{r.status}</Badge>
                      <span className="text-slate-400">{new Date(r.createdAt).toLocaleString()}</span>
                    </li>
                  ))}
                </ul>}
        </Card>
      </div>
    </>
  );
}
