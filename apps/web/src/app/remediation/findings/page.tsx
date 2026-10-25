"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { Badge, Card, EmptyState } from "@zerosweep/ui";
import { apiFetch } from "@/lib/api-client";

interface Dashboard {
  openBacklog: number; p0: number; p1: number; dueSoon: number; overdue: number;
  fixClaimed: number; verificationPending: number; verifiedFixed: number; closed: number;
  regressions: number; totalRegressions: number; exceptions: number;
}
interface QueueItem {
  id: string; status: string; priority: string | null; ownerId: string | null; teamId: string | null;
  dueAt: string | null; verificationState: string; regressionCount: number;
  finding: { title: string; severity: string; cve: string | null; kevListed: boolean; lifecycleStatus: string } | null;
}

/**
 * Remediation orchestration dashboard + queue (Prompt 31 §103/§104).
 * Counters come from live case states; the queue is SLA-ordered.
 * A case is closed ONLY through verification or an approved exception —
 * this UI offers no force-close.
 */
export default function Page() {
  const [dash, setDash] = useState<Dashboard | null>(null);
  const [items, setItems] = useState<QueueItem[]>([]);
  const [status, setStatus] = useState("");
  const [priority, setPriority] = useState("");
  const [search, setSearch] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiFetch<Dashboard>("/remediation/dashboard").then(setDash).catch(() => setDash(null));
  }, []);

  useEffect(() => {
    const params = new URLSearchParams();
    if (status) params.set("status", status);
    if (priority) params.set("priority", priority);
    if (search) params.set("search", search);
    apiFetch<{ items: QueueItem[] }>(`/remediation/queue?${params.toString()}`)
      .then((r) => { setItems(r.items); setError(null); })
      .catch((e: Error) => setError(e.message));
  }, [status, priority, search]);

  const stats: Array<[string, number, string]> = dash ? [
    ["Open backlog", dash.openBacklog, "text-slate-100"],
    ["P0", dash.p0, "text-red-300"],
    ["P1", dash.p1, "text-orange-300"],
    ["Due ≤ 48h", dash.dueSoon, "text-amber-300"],
    ["Overdue", dash.overdue, "text-red-300"],
    ["Fix claimed", dash.fixClaimed, "text-sky-300"],
    ["Verification pending", dash.verificationPending, "text-violet-300"],
    ["Verified fixed", dash.verifiedFixed, "text-emerald-300"],
    ["Closed", dash.closed, "text-slate-300"],
    ["Regressions", dash.totalRegressions, "text-red-300"],
    ["Exceptions", dash.exceptions, "text-slate-300"],
  ] : [];

  return (
    <>
      <PageHeader eyebrow="Remediation" title="Remediation Queue" body="Every canonical finding's remediation case — triage, ownership, SLA, tickets, fix verification and closure. Claimed is not verified; verified is not closed until the closure checks pass." />
      {dash && (
        <div className="mb-4 grid grid-cols-3 gap-3 md:grid-cols-6">
          {stats.map(([label, value, cls]) => (
            <Card key={label}>
              <div className={`text-2xl font-semibold ${cls}`}>{value}</div>
              <div className="text-xs text-slate-400">{label}</div>
            </Card>
          ))}
        </div>
      )}
      <Card>
        <div className="mb-3 flex flex-wrap gap-2">
          <select value={status} onChange={(e) => setStatus(e.target.value)} className="rounded bg-slate-800 px-2 py-1 text-sm">
            <option value="">All statuses</option>
            {["NEW", "TRIAGED", "ASSIGNED", "PLANNED", "IN_PROGRESS", "BLOCKED", "FIX_CLAIMED", "VERIFICATION_PENDING", "VERIFICATION_RUNNING", "VERIFIED_FIXED", "ACCEPTED_RISK", "FALSE_POSITIVE", "DEFERRED", "CLOSED", "REOPENED"].map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <select value={priority} onChange={(e) => setPriority(e.target.value)} className="rounded bg-slate-800 px-2 py-1 text-sm">
            <option value="">All priorities</option>
            {["P0", "P1", "P2", "P3", "P4"].map((p) => <option key={p} value={p}>{p}</option>)}
          </select>
          <input value={search} onChange={(e) => setSearch(e.target.value)} placeholder="Search findings…" className="rounded bg-slate-800 px-2 py-1 text-sm" />
          <Link href="/remediation/sla" className="text-sm text-sky-300 hover:underline">SLA</Link>
          <Link href="/remediation/campaigns" className="text-sm text-sky-300 hover:underline">Campaigns</Link>
          <Link href="/remediation/regressions" className="text-sm text-sky-300 hover:underline">Regressions</Link>
        </div>
        {error && <p className="text-sm text-red-300">{error}</p>}
        {items.length === 0 && !error ? (
          <EmptyState title="No remediation cases" body="Cases are created from canonical findings in the vulnerability queue. Nothing is auto-closed — every closure is verified or exception-approved." />
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-slate-400">
                <th className="py-1">Finding</th><th>Status</th><th>Priority</th><th>Owner</th><th>Due</th><th>Verify</th><th>Regr.</th>
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.id} className="border-t border-slate-800">
                  <td className="py-2">
                    <Link href={`/remediation/${item.id}`} className="text-sky-300 hover:underline">{item.finding?.title ?? item.id}</Link>
                    <span className="text-slate-500"> · {item.finding?.severity ?? ""}{item.finding?.kevListed ? " · KEV" : ""}{item.finding?.cve ? ` · ${item.finding.cve}` : ""}</span>
                  </td>
                  <td><Badge>{item.status}</Badge></td>
                  <td>{item.priority ?? "—"}</td>
                  <td>{item.teamId ?? item.ownerId ?? "unassigned"}</td>
                  <td>{item.dueAt ? new Date(item.dueAt).toLocaleDateString() : "—"}</td>
                  <td>{item.verificationState}</td>
                  <td>{item.regressionCount > 0 ? item.regressionCount : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </>
  );
}
