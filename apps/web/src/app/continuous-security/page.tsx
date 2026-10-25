"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@zerosweep/ui";

/**
 * Continuous Security overview (Prompt 22 §78). Scheduler health,
 * latest posture, drift counters, upcoming runs and the safety
 * contract: scheduled work only ever materializes through the gated
 * paths — verified target + approved assessment + scope + policy are
 * re-checked at EVERY fire time, and a gate refusal is a recorded
 * BLOCKED/SKIPPED run, never a silent retry.
 */
interface Health {
  scheduler: { status: string; leaseOwner?: string | null; heartbeatAt?: string | null };
  activeSchedules: number; dueNow: number; overdueSchedules: number;
  runsLast24h: number; failedOrBlockedLast24h: number; deadLettersLast24h: number;
  latestPostureSnapshotAt?: string | null; note: string;
}
interface PostureRow {
  id: string; capturedAt: string; assetCount: number; findingCount: number;
  kevCount: number; riskScore?: number | null; slaOverdue: number;
}
interface UpcomingRow { scheduleId: string; name: string; kind: string; timezone: string; upcomingRuns: string[] }

const asArray = <T,>(x: T[] | { items: T[] }): T[] => (Array.isArray(x) ? x : x.items ?? []);

export default function Page() {
  const [health, setHealth] = useState<Health | null>(null);
  const [posture, setPosture] = useState<PostureRow[]>([]);
  const [upcoming, setUpcoming] = useState<UpcomingRow[]>([]);
  const [state, setState] = useState<"loading" | "error" | "ready">("loading");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const [h, p, u] = await Promise.all([
        apiFetch<Health>("/monitoring/health"),
        apiFetch<PostureRow[] | { items: PostureRow[] }>("/posture/snapshots"),
        apiFetch<UpcomingRow[] | { items: UpcomingRow[] }>("/schedules/upcoming"),
      ]);
      setHealth(h);
      setPosture(asArray(p));
      setUpcoming(asArray(u));
      setState("ready");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "failed to load continuous security");
      setState("error");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const act = async (path: string, label: string) => {
    setBusy(true);
    try {
      await apiFetch(path, { method: "POST" });
      setNotice(`${label} done`);
      await load();
    } catch (err) {
      setNotice(err instanceof ApiError ? err.message : `${label} failed`);
    } finally { setBusy(false); }
  };

  const latest = posture[0];

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Continuous Security" title="Continuous Security" body="Monitoring policies, the intelligent scheduler, drift detection and automation — every scheduled run re-passes every gate." />
      <div className="flex gap-2 text-sm">
        <Link className="rounded bg-slate-800 px-3 py-1.5 text-slate-200" href="/continuous-security/schedules">Schedules</Link>
        <Link className="rounded bg-slate-800 px-3 py-1.5 text-slate-200" href="/continuous-security/posture">Posture History</Link>
        <Link className="rounded bg-slate-800 px-3 py-1.5 text-slate-200" href="/continuous-security/drift">Drift</Link>
        <Link className="rounded bg-slate-800 px-3 py-1.5 text-slate-200" href="/continuous-security/timeline">Timeline</Link>
        <Link className="rounded bg-slate-800 px-3 py-1.5 text-slate-200" href="/automation/workflows">Workflows</Link>
        <Link className="rounded bg-slate-800 px-3 py-1.5 text-slate-200" href="/notifications">Notifications</Link>
      </div>
      {notice ? <p className="text-sm text-amber-300">{notice}</p> : null}
      {state === "loading" ? <p className="text-slate-400">Loading…</p> : null}
      {state === "error" ? <EmptyState title="Could not load" body={error} /> : null}
      {state === "ready" && health ? (
        <>
          <div className="grid gap-4 md:grid-cols-4">
            <Card><p className="text-xs text-slate-400">Scheduler</p><p className="text-lg text-slate-100">{health.scheduler.status}</p><p className="text-xs text-slate-500">lease: {health.scheduler.leaseOwner ?? "—"}</p></Card>
            <Card><p className="text-xs text-slate-400">Active schedules</p><p className="text-lg text-slate-100">{health.activeSchedules}</p><p className="text-xs text-slate-500">{health.dueNow} due now · {health.overdueSchedules} overdue</p></Card>
            <Card><p className="text-xs text-slate-400">Runs (24h)</p><p className="text-lg text-slate-100">{health.runsLast24h}</p><p className="text-xs text-slate-500">{health.failedOrBlockedLast24h} failed/blocked · {health.deadLettersLast24h} dead-lettered</p></Card>
            <Card><p className="text-xs text-slate-400">Latest posture</p><p className="text-lg text-slate-100">{latest ? (latest.riskScore ?? "—") : "—"}</p><p className="text-xs text-slate-500">{latest ? `${latest.findingCount} findings · ${latest.kevCount} KEV · ${latest.slaOverdue} SLA overdue` : "no snapshot yet"}</p></Card>
          </div>
          <Card>
            <div className="flex items-center justify-between">
              <h3 className="font-medium text-slate-100">Operations</h3>
              <div className="flex gap-2">
                <button disabled={busy} onClick={() => void act("/posture/snapshots", "Snapshot capture")} className="rounded bg-slate-800 px-3 py-1.5 text-sm text-slate-200 disabled:opacity-50">Capture snapshot now</button>
                <button disabled={busy} onClick={() => void act("/monitoring/tick", "Scheduler tick")} className="rounded bg-slate-800 px-3 py-1.5 text-sm text-slate-200 disabled:opacity-50">Run scheduler tick</button>
              </div>
            </div>
            <p className="mt-2 text-sm text-slate-400">{health.note}</p>
            <p className="mt-1 text-sm text-slate-400">
              Safety contract: only SAFE_AUTOMATED profiles can be scheduled. Approval-required, manual-only and
              prohibited automation (credential attacks, exploitation, active wireless, runtime debugging) can
              never become unattended schedules — in code, not just in policy text.
            </p>
          </Card>
          <Card>
            <h3 className="mb-2 font-medium text-slate-100">Upcoming runs</h3>
            {upcoming.length === 0 ? <EmptyState title="No upcoming runs" body="Create a schedule to start continuous monitoring." /> : (
              <ul className="space-y-1 text-sm text-slate-300">
                {upcoming.slice(0, 10).map((u) => (
                  <li key={u.scheduleId} className="flex items-center gap-2">
                    <Badge>{u.kind}</Badge>
                    <span className="text-slate-100">{u.name}</span>
                    <span className="text-slate-500">{u.upcomingRuns[0] ?? "—"} ({u.timezone})</span>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </>
      ) : null}
    </div>
  );
}
