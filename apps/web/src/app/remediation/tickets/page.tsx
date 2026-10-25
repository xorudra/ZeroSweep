"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { Badge, Card, EmptyState } from "@zerosweep/ui";
import { apiFetch } from "@/lib/api-client";

interface TicketsData {
  tickets: Array<Record<string, unknown>>;
  openConflicts: Array<Record<string, unknown>>;
}

/**
 * Remediation tickets (Prompt 24 §94): findings and their external
 * tickets, mapped statuses, owners, sync state and open conflicts.
 * A CLOSED ticket is not a resolved finding (§52) — resolution still
 * requires evidence and retest in the platform lifecycle.
 */
export default function Page() {
  const [data, setData] = useState<TicketsData | null>(null);
  const [message, setMessage] = useState<string | null>(null);
  const load = useCallback(() => {
    apiFetch<TicketsData>("/remediation/tickets").then(setData).catch(() => setData({ tickets: [], openConflicts: [] }));
  }, []);
  useEffect(() => { load(); }, [load]);

  const sync = async (id: string) => {
    try {
      await apiFetch(`/remediation/tickets/${id}/sync`, { method: "POST", body: JSON.stringify({}) });
      setMessage("Ticket sync attempted — see the sync state column.");
      load();
    } catch (e) {
      setMessage(e instanceof Error ? e.message : "Sync failed");
    }
  };

  return (
    <>
      <PageHeader
        eyebrow="Remediation · Tickets"
        title="Remediation Tickets"
        body="One external ticket per finding and integration — duplicates are prevented. Sync conflicts are surfaced for an analyst decision; the platform never silently overwrites either side."
      />
      {message ? <p className="mb-4 text-sm text-sky-300">{message}</p> : null}
      {!data ? <p className="text-sm text-slate-400">Loading…</p> : null}
      {data && data.openConflicts.length > 0 ? (
        <Card>
          <h2 className="text-base font-semibold text-amber-300">Open sync conflicts ({data.openConflicts.length})</h2>
          <ul className="mt-2 space-y-1 text-sm text-slate-300">
            {data.openConflicts.map((c, i) => (
              <li key={i}>
                Field <span className="text-slate-100">{String(c.field)}</span> — local: {String(c.localValue ?? "—")} · external: {String(c.externalValue ?? "—")}
                {" "}(ticket {String(c.ticketId).slice(0, 8)}…)
              </li>
            ))}
          </ul>
        </Card>
      ) : null}
      {data ? (
        <Card>
          <h2 className="text-base font-semibold text-slate-100">Tickets</h2>
          {data.tickets.length === 0 ? (
            <EmptyState title="No tickets yet" body="Create a ticket from a finding once a Jira project mapping exists for the workspace." />
          ) : (
            <table className="mt-3 w-full text-sm">
              <thead>
                <tr className="text-left text-slate-400">
                  <th className="px-2 py-1">Finding</th><th className="px-2 py-1">External ticket</th>
                  <th className="px-2 py-1">Status</th><th className="px-2 py-1">Assignee ref</th>
                  <th className="px-2 py-1">Sync state</th><th className="px-2 py-1">Last sync</th><th className="px-2 py-1">Actions</th>
                </tr>
              </thead>
              <tbody>
                {data.tickets.map((t, i) => (
                  <tr key={i} className="border-t border-slate-800">
                    <td className="px-2 py-2">
                      <Link href={`/findings/${String(t.findingId)}`} className="text-sky-300 hover:underline">{String(t.findingId).slice(0, 8)}…</Link>
                    </td>
                    <td className="px-2 py-2 text-slate-200">
                      {t.externalUrl ? (
                        <a href={String(t.externalUrl)} target="_blank" rel="noreferrer" className="text-sky-300 hover:underline">{String(t.externalKey ?? t.externalId ?? "")}</a>
                      ) : (t.externalKey ? String(t.externalKey) : "Not created externally")}
                    </td>
                    <td className="px-2 py-2">
                      <Badge tone={t.status === "CLOSED" ? "neutral" : t.status === "RESOLVED" ? "ok" : t.status === "IN_PROGRESS" ? "high" : "medium"}>{String(t.status ?? "")}</Badge>
                    </td>
                    <td className="px-2 py-2 text-slate-300">{String(t.assigneeReference ?? "—")}</td>
                    <td className="px-2 py-2 text-slate-300">{String(t.syncState ?? "")}</td>
                    <td className="px-2 py-2 text-slate-300">{t.lastSyncedAt ? new Date(String(t.lastSyncedAt)).toLocaleString() : "—"}</td>
                    <td className="px-2 py-2">
                      <button type="button" onClick={() => sync(String(t.id))} className="rounded border border-slate-600 px-2 py-1 text-xs text-slate-200">Sync</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      ) : null}
    </>
  );
}
