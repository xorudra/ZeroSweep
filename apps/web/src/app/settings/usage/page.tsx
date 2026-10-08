"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Usage view (Prompt 40 §107/§108): current plan, period, measured
 * usage per metric and per-dimension quota state. Every number comes
 * from real metering rows — nothing is estimated or invented (§44).
 */
interface QuotaRow { dimension: string; currentUsage: number; limit: number | null; source: string; overLimit: boolean }
interface UsageRow { metric: string; quantity: number; eventCount: number }
interface UsageView {
  plan: { planVersionId: string; status: string; periodStart: string | null; periodEnd: string | null } | null;
  usage: UsageRow[]; quotas: QuotaRow[]; period: { from: string; to: string };
}

export default function Page() {
  const [view, setView] = useState<UsageView | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      setView(await apiFetch<UsageView>("/product/usage"));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Settings" title="Usage" body="Measured usage and quota state for your organization. Usage is recorded from real platform events; dimensions without a plan limit show no limit rather than an invented one." />
      {error && <Card><p className="text-sm text-red-300">{error}</p></Card>}
      {!view && !error && <EmptyState title="Loading usage…" body="Fetching measured usage for your organization." />}
      {view && (
        <>
          <Card>
            <div className="flex flex-wrap items-center gap-3">
              <h2 className="text-base font-semibold">Current period</h2>
              {view.plan ? <Badge>{view.plan.status}</Badge> : <Badge>No subscription</Badge>}
              <span className="text-sm text-slate-400">
                {new Date(view.period.from).toLocaleDateString()} – {new Date(view.period.to).toLocaleDateString()}
                {view.plan?.periodEnd ? ` · Renews ${new Date(view.plan.periodEnd).toLocaleDateString()}` : ""}
              </span>
            </div>
          </Card>
          <Card>
            <h2 className="mb-3 text-base font-semibold">Quotas</h2>
            {view.quotas.length === 0 ? <EmptyState title="No quota dimensions" body="No quota dimensions are tracked for this organization." /> : (
              <ul className="space-y-3">
                {view.quotas.map((q) => (
                  <li key={q.dimension}>
                    <div className="flex items-center justify-between text-sm">
                      <span className="font-medium">{q.dimension.replaceAll("_", " ")}</span>
                      <span className="text-slate-400">
                        {q.currentUsage.toLocaleString()} / {q.limit === null ? "No limit" : q.limit.toLocaleString()} · {q.source}
                      </span>
                    </div>
                    {q.limit !== null && (
                      <div className="mt-1 h-2 rounded bg-slate-800">
                        <div className={`h-2 rounded ${q.overLimit ? "bg-red-500" : "bg-emerald-500"}`} style={{ width: `${Math.min(100, (q.currentUsage / Math.max(1, q.limit)) * 100)}%` }} />
                      </div>
                    )}
                    {q.overLimit && <p className="mt-1 text-xs text-red-300">Over limit: existing data stays readable and exportable; new creation beyond the limit is blocked (§118).</p>}
                  </li>
                ))}
              </ul>
            )}
          </Card>
          <Card>
            <h2 className="mb-3 text-base font-semibold">Metered usage (period)</h2>
            {view.usage.length === 0 ? <EmptyState title="No usage recorded" body="No metering events were recorded in this period." /> : (
              <table className="w-full text-sm">
                <thead><tr className="text-left text-slate-400"><th className="py-1">Metric</th><th>Quantity</th><th>Events</th></tr></thead>
                <tbody>
                  {view.usage.map((u) => (
                    <tr key={u.metric} className="border-t border-slate-800">
                      <td className="py-1">{u.metric}</td><td>{u.quantity.toLocaleString()}</td><td>{u.eventCount}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
