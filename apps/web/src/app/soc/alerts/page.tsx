"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Alert queue (Prompt 28 §103). Alerts exist only because a
 * detection, correlation pattern or indicator match over recorded
 * telemetry raised them — the queue is empty until real signals land.
 */
interface AlertRow {
  id: string; title: string; severity: string; priority: string; status: string; source: string;
  occurrenceCount: number; firstSeen: string; slaBreached: boolean; ownerId?: string | null;
}

export default function Page() {
  const [items, setItems] = useState<AlertRow[]>([]);
  const [status, setStatus] = useState("");
  const [priority, setPriority] = useState("");
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const qs = new URLSearchParams();
      if (status) qs.set("status", status);
      if (priority) qs.set("priority", priority);
      const out = await apiFetch<{ items: AlertRow[] }>(`/soc/alerts?${qs.toString()}`);
      setItems(out.items);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, [status, priority]);

  useEffect(() => { void load(); }, [load]);

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Security Operations" title="Alert Queue" body="Deduped by fingerprint — repeat detections bump occurrence counts instead of flooding the queue (§32)." />
      {error && <p className="text-sm text-red-400">{error}</p>}
      <div className="flex gap-3">
        <select className="rounded bg-slate-800 px-2 py-1 text-sm" value={status} onChange={(e) => setStatus(e.target.value)}>
          <option value="">All statuses</option>
          {["NEW", "TRIAGED", "INVESTIGATING", "CONTAINED", "RESOLVED", "CLOSED", "DUPLICATE"].map((s) => <option key={s} value={s}>{s}</option>)}
        </select>
        <select className="rounded bg-slate-800 px-2 py-1 text-sm" value={priority} onChange={(e) => setPriority(e.target.value)}>
          <option value="">All priorities</option>
          {["P1", "P2", "P3", "P4"].map((p) => <option key={p} value={p}>{p}</option>)}
        </select>
      </div>
      <Card title={`${items.length} alert(s)`}>
        {items.length === 0 ? (
          <EmptyState title="No alerts match. Alerts appear when detections, correlations or indicator matches fire over ingested telemetry." body="" />
        ) : (
          <ul className="divide-y divide-slate-800">
            {items.map((a) => (
              <li key={a.id} className="py-2">
                <Link href={`/soc/alerts/${a.id}`} className="text-sm text-indigo-300 hover:underline">{a.title}</Link>
                <div className="mt-1 flex flex-wrap gap-2 text-xs text-slate-400">
                  <Badge>{a.priority}</Badge><Badge>{a.severity}</Badge><Badge>{a.status}</Badge>
                  <span>source: {a.source}</span><span>×{a.occurrenceCount}</span>
                  <span>{new Date(a.firstSeen).toLocaleString()}</span>
                  {a.slaBreached && <span className="text-red-400">SLA BREACHED</span>}
                  {a.ownerId && <span>owner: {a.ownerId}</span>}
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
