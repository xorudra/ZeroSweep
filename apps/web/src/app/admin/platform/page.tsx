"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Platform admin (Prompt 38 §197): live service health, release
 * identity, dependency status, queue backlogs, storage, backups and
 * SLO evaluations from the platform-ops API. Every value is measured
 * or persisted — unmeasured SLOs say INSUFFICIENT_DATA (§127).
 */
interface Overview {
  status: string;
  checks: Record<string, { status: string; detail?: string }>;
  release: { version: string; commit: string; environment: string };
  control: { maintenanceMode: boolean; maintenanceMessage?: string; killSwitches: Record<string, { enabled: boolean; reason?: string }> };
  productionConfig: { ok: boolean; mode: string; violations: Array<{ group: string; rule: string }> };
  queues: Array<{ name: string; waiting: number; active: number; failed: number }>;
  storage: { endpoint: string; status: string; note: string };
  backups: { latest: { kind: string; status: string; startedAt: string; encrypted: boolean } | null };
  generatedAt: string;
}
interface SloItem { name: string; kind: string; target: number; result: { status: string; ratio: number | null; successes: number; total: number } }

export default function Page() {
  const [overview, setOverview] = useState<Overview | null>(null);
  const [slos, setSlos] = useState<SloItem[]>([]);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const [o, s] = await Promise.all([
        apiFetch<Overview>("/platform/overview"),
        apiFetch<{ items: SloItem[] }>("/platform/slos"),
      ]);
      setOverview(o);
      setSlos(s.items ?? []);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Platform Operations" title="Platform Admin" body="Deployment health, release identity, operator controls and measured SLOs for this DSRclone installation. Platform operations require the platform RBAC permissions (§203)." />
      {error && <p className="rounded bg-red-950/60 px-3 py-2 text-sm text-red-300">{error}</p>}
      <div className="flex gap-3 text-sm">
        <Link className="text-sky-400 underline" href="/admin/platform/queues">Queues</Link>
        <Link className="text-sky-400 underline" href="/admin/platform/workers">Workers</Link>
        <Link className="text-sky-400 underline" href="/admin/platform/backups">Backups</Link>
      </div>
      {!overview && !error && <EmptyState title="Loading" body="Reading live platform state…" />}
      {overview && (
        <>
          <div className="grid gap-4 md:grid-cols-3">
            <Card>
              <p className="text-xs uppercase text-slate-500">Platform status</p>
              <p className="mt-1 text-lg text-slate-100"><Badge>{overview.status}</Badge></p>
              <div className="mt-2 space-y-1 text-sm text-slate-400">
                {Object.entries(overview.checks).map(([k, v]) => (
                  <p key={k}>{k}: {v.status}{v.detail ? ` — ${v.detail}` : ""}</p>
                ))}
              </div>
            </Card>
            <Card>
              <p className="text-xs uppercase text-slate-500">Release</p>
              <p className="mt-1 text-sm text-slate-300">version {overview.release.version}</p>
              <p className="text-sm text-slate-400">commit {overview.release.commit}</p>
              <p className="text-sm text-slate-400">environment {overview.release.environment}</p>
              <p className="mt-2 text-sm text-slate-400">
                production config: {overview.productionConfig.ok ? "valid" : `${overview.productionConfig.violations.length} violation(s)`}
              </p>
            </Card>
            <Card>
              <p className="text-xs uppercase text-slate-500">Operator controls</p>
              <p className="mt-1 text-sm text-slate-300">
                maintenance mode: {overview.control.maintenanceMode ? `ON${overview.control.maintenanceMessage ? ` — ${overview.control.maintenanceMessage}` : ""}` : "off"}
              </p>
              <div className="mt-1 space-y-1 text-sm text-slate-400">
                {Object.entries(overview.control.killSwitches).map(([k, v]) => (
                  <p key={k}>{k}: {v.enabled ? `ENABLED${v.reason ? ` (${v.reason})` : ""}` : "off"}</p>
                ))}
                {Object.keys(overview.control.killSwitches).length === 0 && <p>no kill switches set</p>}
              </div>
            </Card>
          </div>
          <Card>
            <p className="text-xs uppercase text-slate-500">Storage & backups</p>
            <p className="mt-1 text-sm text-slate-300">object storage: {overview.storage.status} · {overview.storage.endpoint}</p>
            <p className="text-sm text-slate-400">{overview.storage.note}</p>
            <p className="mt-1 text-sm text-slate-300">
              latest backup: {overview.backups.latest
                ? `${overview.backups.latest.kind} · ${overview.backups.latest.status} · ${overview.backups.latest.startedAt}${overview.backups.latest.encrypted ? " · encrypted" : ""}`
                : "none recorded yet"}
            </p>
          </Card>
          <Card>
            <p className="text-xs uppercase text-slate-500">Service level objectives (measured only)</p>
            <div className="mt-2 divide-y divide-slate-800">
              {slos.map((s) => (
                <div key={s.name} className="flex flex-wrap items-center gap-3 py-2 text-sm">
                  <span className="text-slate-200">{s.name}</span>
                  <Badge>{s.result.status}</Badge>
                  <span className="text-slate-400">
                    {s.result.ratio === null
                      ? "no measured samples in window — no figure claimed (§127)"
                      : `measured ${(s.result.ratio * 100).toFixed(2)}% over ${s.result.total} samples · target ${(s.target * 100).toFixed(0)}%`}
                  </span>
                </div>
              ))}
              {slos.length === 0 && <p className="py-2 text-sm text-slate-400">No SLO definitions.</p>}
            </div>
          </Card>
          <p className="text-xs text-slate-500">Generated {overview.generatedAt} · queue backlog total {overview.queues.reduce((a, q) => a + q.waiting + q.active + q.failed, 0)} jobs across {overview.queues.length} queues</p>
        </>
      )}
    </div>
  );
}
