"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { Badge, Card } from "@zerosweep/ui";
import { apiFetch } from "@/lib/api-client";

interface ReportRow {
  id: string; title: string; type: string; status: string; approvalStatus: string;
  version: string; classification: string; createdAt: string;
  exports?: { format: string; status: string }[];
}

const REPORT_TYPES = [
  "EXECUTIVE", "TECHNICAL", "CLIENT", "COMPLIANCE", "AUDIT", "ASSESSMENT", "RETEST",
  "CLOUD", "KUBERNETES", "CODE_SECURITY", "API_SECURITY", "MOBILE", "ACTIVE_DIRECTORY", "TREND", "CUSTOM",
];

/**
 * Unified security reports (Prompt 20 §55–§59). Generation builds an
 * immutable snapshot from stored findings only — it never runs a scan.
 * Exports render asynchronously in the worker; a QUEUED export is shown
 * as queued, never as ready.
 */
export default function SecurityReportsPage() {
  const [reports, setReports] = useState<ReportRow[]>([]);
  const [title, setTitle] = useState("");
  const [type, setType] = useState("EXECUTIVE");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = () => apiFetch<ReportRow[]>("/security-reports").then(setReports).catch((e: Error) => setError(e.message));
  useEffect(() => { load(); }, []);

  const create = async () => {
    setBusy(true); setError(null);
    try {
      await apiFetch("/security-reports", { method: "POST", body: JSON.stringify({ title, type }) });
      setTitle("");
      await load();
    } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  };

  const generate = async (id: string) => {
    setBusy(true); setError(null);
    try {
      await apiFetch(`/security-reports/${id}/generate`, { method: "POST", body: "{}" });
      await load();
    } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  };

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Reporting" title="Security Reports" body="Unified reporting across every assessment domain — snapshots are immutable once issued." />
      {error ? <Card><p className="text-sm text-red-400">{error}</p></Card> : null}
      <Card>
        <h3 className="mb-3 text-sm font-semibold text-slate-200">New report</h3>
        <div className="flex flex-wrap items-end gap-3">
          <label className="text-xs text-slate-400">Title
            <input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="e.g. Q4 Executive Report" className="mt-1 block w-64 rounded bg-slate-800 px-2 py-1.5 text-sm text-slate-100" />
          </label>
          <label className="text-xs text-slate-400">Type
            <select value={type} onChange={(e) => setType(e.target.value)} className="mt-1 block rounded bg-slate-800 px-2 py-1.5 text-sm text-slate-100">
              {REPORT_TYPES.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
          </label>
          <button onClick={create} disabled={busy || !title.trim()} className="rounded bg-sky-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-sky-500 disabled:opacity-50">Create draft</button>
        </div>
        <p className="mt-2 text-xs text-slate-500">Reports render only stored records. An empty scope produces an honest empty report — never placeholder statistics.</p>
      </Card>
      <Card>
        <h3 className="mb-3 text-sm font-semibold text-slate-200">Reports</h3>
        {reports.length === 0 ? (
          <p className="text-sm text-slate-500">No reports yet.</p>
        ) : (
          <ul className="divide-y divide-slate-800">
            {reports.map((r) => (
              <li key={r.id} className="flex flex-wrap items-center gap-3 py-2 text-sm">
                <Link href={`/security-reports/${r.id}`} className="font-medium text-slate-100 hover:underline">{r.title}</Link>
                <Badge tone="slate">{r.type}</Badge>
                <Badge tone="slate">{r.classification}</Badge>
                <Badge tone={r.status === "READY" ? "green" : "slate"}>{r.status}</Badge>
                <Badge tone="slate">{r.approvalStatus}</Badge>
                <span className="text-xs text-slate-500">{r.version} · {new Date(r.createdAt).toLocaleDateString()}</span>
                <span className="ml-auto flex gap-2">
                  {(r.exports ?? []).map((e) => <Badge key={e.format} tone={e.status === "READY" ? "green" : "slate"}>{e.format} {e.status}</Badge>)}
                  <button onClick={() => generate(r.id)} disabled={busy || r.approvalStatus === "ISSUED"} className="rounded bg-sky-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-sky-500 disabled:opacity-50">Generate</button>
                </span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
