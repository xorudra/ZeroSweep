"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Incident queue (Prompt 28 §105). Incidents are declared manually,
 * escalated from alerts, or escalated from investigation cases —
 * never auto-fabricated from templates.
 */
interface IncidentRow {
  id: string; title: string; severity: string; priority: string; status: string;
  declaredAt: string; commanderId?: string | null; category?: string | null;
}

export default function Page() {
  const [items, setItems] = useState<IncidentRow[]>([]);
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState("HIGH");
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const out = await apiFetch<{ items: IncidentRow[] }>("/soc/incidents");
      setItems(out.items);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const create = async () => {
    if (!title.trim()) return;
    try {
      await apiFetch("/soc/incidents", { method: "POST", body: JSON.stringify({ title, severity }) });
      setTitle("");
      await load();
    } catch (e) { setError(e instanceof ApiError ? e.message : "Create failed."); }
  };

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Security Operations" title="Incidents" body="Coordinated response with append-only timelines, hash-anchored evidence and governed response actions." />
      {error && <p className="text-sm text-red-400">{error}</p>}
      <Card title="Declare incident (manual, §43)">
        <div className="flex flex-wrap gap-2">
          <input className="min-w-64 flex-1 rounded bg-slate-800 px-2 py-1 text-sm" placeholder="Incident title" value={title} onChange={(e) => setTitle(e.target.value)} />
          <select className="rounded bg-slate-800 px-2 py-1 text-sm" value={severity} onChange={(e) => setSeverity(e.target.value)}>
            {["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <button className="rounded bg-indigo-600 px-3 py-1 text-sm text-white" onClick={create}>Declare</button>
        </div>
      </Card>
      <Card title={`${items.length} incident(s)`}>
        {items.length === 0 ? (
          <EmptyState title="No incidents. Declare one above, or escalate an alert / investigation case." body="" />
        ) : (
          <ul className="divide-y divide-slate-800">
            {items.map((i) => (
              <li key={i.id} className="py-2">
                <Link href={`/soc/incidents/${i.id}`} className="text-sm text-indigo-300 hover:underline">{i.title}</Link>
                <div className="mt-1 flex flex-wrap gap-2 text-xs text-slate-400">
                  <Badge>{i.priority}</Badge><Badge>{i.severity}</Badge><Badge>{i.status}</Badge>
                  <span>declared {new Date(i.declaredAt).toLocaleString()}</span>
                  {i.commanderId && <span>commander: {i.commanderId}</span>}
                  {i.category && <span>{i.category}</span>}
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
