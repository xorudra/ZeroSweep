"use client";

import { Card } from "@dsrclone/ui";
import { CountTable, DashboardShell, Stat, hours, useAnalytics } from "../DashboardShared";

interface Remediation {
  overdue: { findingId: string; title: string; severity: string; dueAt: string }[];
  dueSoon: { findingId: string; title: string; severity: string; dueAt: string }[];
  unassigned: number;
  byPriority: Record<string, number>;
  resolvedCount: number;
  mttrHours: number | null;
}

/** Remediation dashboard (Prompt 20 §73): SLA posture and ownership. */
export default function RemediationDashboardPage() {
  const { data, error } = useAnalytics<Remediation>("/analytics/remediation");
  return (
    <DashboardShell title="Remediation" subtitle="SLA posture, ownership gaps and mean time to remediate.">
      {error ? <Card><p className="text-sm text-red-400">{error}</p></Card> : null}
      {!data ? <Card><p className="text-sm text-slate-400">Loading…</p></Card> : (
        <>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <Stat label="Overdue" value={data.overdue.length} />
            <Stat label="Due within 7 days" value={data.dueSoon.length} />
            <Stat label="Unassigned" value={data.unassigned} />
            <Stat label="MTTR" value={hours(data.mttrHours)} hint={`${data.resolvedCount} resolved findings measured`} />
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <h3 className="mb-2 text-sm font-semibold text-slate-200">Overdue findings</h3>
              {data.overdue.length === 0 ? (
                <p className="text-xs text-slate-500">No data in scope — nothing is overdue.</p>
              ) : (
                <ul className="space-y-1">
                  {data.overdue.slice(0, 20).map((f) => (
                    <li key={f.findingId} className="flex items-center justify-between text-sm">
                      <span className="text-slate-300">{f.title}</span>
                      <span className="text-slate-400">{f.severity} · due {new Date(f.dueAt).toLocaleDateString()}</span>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
            <CountTable title="Open by priority" rows={data.byPriority} />
          </div>
        </>
      )}
    </DashboardShell>
  );
}
