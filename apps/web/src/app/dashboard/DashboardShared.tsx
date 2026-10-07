"use client";

import { useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { Badge, Card } from "@dsrclone/ui";
import { apiFetch } from "@/lib/api-client";

export function Stat({ label, value, hint }: { label: string; value: React.ReactNode; hint?: string }) {
  return (
    <Card>
      <div className="text-xs uppercase tracking-wide text-slate-500">{label}</div>
      <div className="mt-1 text-2xl font-semibold text-slate-100">{value}</div>
      {hint ? <div className="mt-1 text-xs text-slate-500">{hint}</div> : null}
    </Card>
  );
}

export function CountTable({ title, rows }: { title: string; rows: Record<string, number> }) {
  const entries = Object.entries(rows).sort((a, b) => b[1] - a[1]);
  return (
    <Card>
      <h3 className="mb-2 text-sm font-semibold text-slate-200">{title}</h3>
      {entries.length === 0 ? (
        <p className="text-xs text-slate-500">No data in scope — nothing recorded yet.</p>
      ) : (
        <ul className="space-y-1">
          {entries.map(([k, v]) => (
            <li key={k} className="flex items-center justify-between text-sm">
              <span className="text-slate-300">{k}</span>
              <Badge tone="slate">{v}</Badge>
            </li>
          ))}
        </ul>
      )}
    </Card>
  );
}

/** Shared loader for the Prompt 20 dashboards: every number comes from
 *  the unified analytics API over stored findings — nothing is invented
 *  client-side, and an empty workspace renders honest zeros. */
export function useAnalytics<T>(path: string) {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    apiFetch<T>(path)
      .then(setData)
      .catch((e: Error) => setError(e.message));
  }, [path]);
  return { data, error };
}

export function DashboardShell({ title, subtitle, children }: { title: string; subtitle: string; children: React.ReactNode }) {
  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Analytics" title={title} body={subtitle} />
      {children}
    </div>
  );
}

export function pct(value: number | null | undefined): string {
  return value === null || value === undefined ? "—" : `${value}%`;
}

export function hours(value: number | null | undefined): string {
  return value === null || value === undefined ? "—" : `${value}h`;
}
