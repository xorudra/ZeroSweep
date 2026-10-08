"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Card, EmptyState } from "@dsrclone/ui";

/**
 * Posture history (Prompt 22 §80). Immutable snapshots only — the
 * history is read from stored captures, never recomputed from
 * current state. The daily summary is generated from the day's
 * stored records with citations and is labelled RULE_BASED (no AI
 * provider is configured; nothing here pretends otherwise, §76/§77).
 */
interface PostureRow {
  id: string; capturedAt: string; source: string; assetCount: number; findingCount: number;
  findingsBySeverity: Record<string, number>; kevCount: number; verifiedFindings: number;
  slaOverdue: number; slaDueSoon: number; coverage?: number | null; riskScore?: number | null;
}
interface SummaryRow {
  id: string; date: string; generator: string;
  summary: { highlights?: string[]; counts?: Record<string, number> };
  citations: string[];
}

const inputCls = "rounded bg-slate-900 px-2 py-1.5 text-sm text-slate-200 border border-slate-700";
const asArray = <T,>(x: T[] | { items: T[] }): T[] => (Array.isArray(x) ? x : x.items ?? []);

export default function Page() {
  const [snapshots, setSnapshots] = useState<PostureRow[]>([]);
  const [summaries, setSummaries] = useState<SummaryRow[]>([]);
  const [state, setState] = useState<"loading" | "error" | "ready">("loading");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [date, setDate] = useState(new Date().toISOString().slice(0, 10));
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const [p, s] = await Promise.all([
        apiFetch<PostureRow[] | { items: PostureRow[] }>("/posture/snapshots"),
        apiFetch<SummaryRow[] | { items: SummaryRow[] }>("/posture/daily-summary"),
      ]);
      setSnapshots(asArray(p));
      setSummaries(asArray(s));
      setState("ready");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "failed to load posture history");
      setState("error");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const generate = async () => {
    setBusy(true);
    try {
      await apiFetch("/posture/daily-summary", { method: "POST", body: JSON.stringify({ date }) });
      setNotice(`Daily summary for ${date} generated from stored records.`);
      await load();
    } catch (err) {
      setNotice(err instanceof ApiError ? err.message : "generation failed");
    } finally { setBusy(false); }
  };

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Continuous Security" title="Posture History" body="Immutable security posture snapshots with rollups and grounded daily summaries." />
      {notice ? <p className="text-sm text-amber-300">{notice}</p> : null}
      {state === "loading" ? <p className="text-slate-400">Loading…</p> : null}
      {state === "error" ? <EmptyState title="Could not load" body={error} /> : null}
      {state === "ready" ? (
        <>
          <Card>
            <h3 className="mb-2 font-medium text-slate-100">Snapshots</h3>
            {snapshots.length === 0 ? <EmptyState title="No snapshots" body="Capture a snapshot from the Continuous Security overview, or let a schedule do it." /> : (
              <table className="w-full text-left text-sm text-slate-300">
                <thead><tr className="text-slate-500"><th className="py-1">Captured</th><th>Source</th><th>Assets</th><th>Findings</th><th>KEV</th><th>Verified</th><th>SLA overdue</th><th>Risk</th></tr></thead>
                <tbody>
                  {snapshots.map((s) => (
                    <tr key={s.id} className="border-t border-slate-800">
                      <td className="py-1.5">{new Date(s.capturedAt).toLocaleString()}</td>
                      <td>{s.source}</td>
                      <td>{s.assetCount}</td>
                      <td>{s.findingCount}</td>
                      <td>{s.kevCount}</td>
                      <td>{s.verifiedFindings}</td>
                      <td>{s.slaOverdue}</td>
                      <td>{s.riskScore ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>
          <Card>
            <h3 className="mb-3 font-medium text-slate-100">AI daily summary (grounded, cited)</h3>
            <div className="mb-3 flex gap-2">
              <input type="date" className={inputCls} value={date} onChange={(e) => setDate(e.target.value)} />
              <button disabled={busy} onClick={() => void generate()} className="rounded bg-emerald-700 px-3 py-1.5 text-sm text-white disabled:opacity-50">Generate summary</button>
            </div>
            {summaries.length === 0 ? <p className="text-sm text-slate-500">No summaries yet.</p> : summaries.map((s) => (
              <div key={s.id} className="mb-3 border-t border-slate-800 pt-2">
                <p className="text-sm text-slate-100">{s.date} <span className="ml-2 rounded bg-slate-800 px-2 py-0.5 text-xs text-slate-300">{s.generator}</span></p>
                <ul className="mt-1 list-disc space-y-0.5 pl-5 text-sm text-slate-300">
                  {(s.summary.highlights ?? []).map((h, i) => <li key={i}>{h}</li>)}
                </ul>
                <p className="mt-1 text-xs text-slate-500">Citations: {s.citations.length} stored record(s). The summary can describe posture only — it can never launch scans (§75).</p>
              </div>
            ))}
          </Card>
        </>
      ) : null}
    </div>
  );
}
