"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@zerosweep/ui";

/**
 * Security schedules (Prompt 22 §81/§82). Create governed recurring
 * schedules (scan / report / revalidation / intel-sync / retest),
 * pause/resume, and run-now — run-now still passes EVERY policy
 * check. Intrusive profiles are refused by the API: the profile of a
 * scan schedule is the approved assessment's own profile snapshot.
 */
interface ScheduleRow {
  id: string; name: string; kind: string; profile?: string | null; expression: string;
  timezone: string; nextRunAt: string; lastStatus?: string | null; enabled: boolean;
  paused: boolean; missedRunPolicy: string; failureCount: number;
}
interface RunRow {
  id: string; scheduleId: string; status: string; reasonCode?: string | null;
  reason?: string | null; scheduledFor: string; scanId?: string | null;
}

const inputCls = "rounded bg-slate-900 px-2 py-1.5 text-sm text-slate-200 border border-slate-700";
const asArray = <T,>(x: T[] | { items: T[] }): T[] => (Array.isArray(x) ? x : x.items ?? []);

export default function Page() {
  const [schedules, setSchedules] = useState<ScheduleRow[]>([]);
  const [runs, setRuns] = useState<RunRow[]>([]);
  const [state, setState] = useState<"loading" | "error" | "ready">("loading");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [name, setName] = useState("");
  const [kind, setKind] = useState("SCAN");
  const [assessmentId, setAssessmentId] = useState("");
  const [reportScheduleId, setReportScheduleId] = useState("");
  const [frequency, setFrequency] = useState("DAILY");
  const [cronExpression, setCronExpression] = useState("");
  const [timezone, setTimezone] = useState("UTC");
  const [missedRunPolicy, setMissedRunPolicy] = useState("RUN_ONCE");

  const load = useCallback(async () => {
    try {
      const [s, r] = await Promise.all([
        apiFetch<ScheduleRow[] | { items: ScheduleRow[] }>("/schedules"),
        apiFetch<RunRow[] | { items: RunRow[] }>("/schedules/runs"),
      ]);
      setSchedules(asArray(s));
      setRuns(asArray(r));
      setState("ready");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "failed to load schedules");
      setState("error");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const create = async () => {
    setBusy(true);
    try {
      await apiFetch("/schedules", {
        method: "POST",
        body: JSON.stringify({
          name, kind, frequency, timezone, missedRunPolicy,
          ...(cronExpression ? { cronExpression } : {}),
          ...(kind === "SCAN" && assessmentId ? { assessmentId } : {}),
          ...(kind === "REPORT" && reportScheduleId ? { reportScheduleId } : {}),
        }),
      });
      setNotice("Schedule created — authorization was verified at creation and will be re-verified before every run.");
      setName("");
      await load();
    } catch (err) {
      setNotice(err instanceof ApiError ? err.message : "create failed");
    } finally { setBusy(false); }
  };

  const act = async (id: string, action: "run" | "pause" | "resume" | "delete") => {
    setBusy(true);
    try {
      if (action === "delete") await apiFetch(`/schedules/${id}`, { method: "DELETE" });
      else {
        const out = await apiFetch<{ status?: string; reason?: string }>(`/schedules/${id}/${action}`, { method: "POST" });
        if (action === "run") setNotice(`Run outcome: ${out.status ?? "done"}${out.reason ? ` — ${out.reason}` : ""}`);
      }
      await load();
    } catch (err) {
      setNotice(err instanceof ApiError ? err.message : `${action} failed`);
    } finally { setBusy(false); }
  };

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Continuous Security" title="Security Schedules" body="Governed recurrence — bounded frequency, maintenance/blackout windows, missed-run policies, per-workspace budgets. A schedule never bypasses a gate." />
      {notice ? <p className="text-sm text-amber-300">{notice}</p> : null}
      <Card>
        <h3 className="mb-3 font-medium text-slate-100">New schedule</h3>
        <div className="flex flex-wrap gap-2">
          <input className={inputCls} placeholder="Name" value={name} onChange={(e) => setName(e.target.value)} />
          <select className={inputCls} value={kind} onChange={(e) => setKind(e.target.value)}>
            <option value="SCAN">Scan</option>
            <option value="REPORT">Report</option>
            <option value="REVALIDATION">Revalidation</option>
            <option value="INTEL_SYNC">Intel sync</option>
            <option value="RETEST">Retest</option>
          </select>
          {kind === "SCAN" ? <input className={inputCls} placeholder="Assessment ID (approved)" value={assessmentId} onChange={(e) => setAssessmentId(e.target.value)} /> : null}
          {kind === "REPORT" ? <input className={inputCls} placeholder="Report schedule ID" value={reportScheduleId} onChange={(e) => setReportScheduleId(e.target.value)} /> : null}
          <select className={inputCls} value={frequency} onChange={(e) => setFrequency(e.target.value)}>
            <option value="HOURLY">Hourly</option>
            <option value="DAILY">Daily</option>
            <option value="WEEKLY">Weekly</option>
            <option value="MONTHLY">Monthly</option>
            <option value="CUSTOM">Custom cron</option>
          </select>
          {frequency === "CUSTOM" ? <input className={inputCls} placeholder="0 2 * * *" value={cronExpression} onChange={(e) => setCronExpression(e.target.value)} /> : null}
          <input className={inputCls} placeholder="Timezone (e.g. Asia/Kolkata)" value={timezone} onChange={(e) => setTimezone(e.target.value)} />
          <select className={inputCls} value={missedRunPolicy} onChange={(e) => setMissedRunPolicy(e.target.value)}>
            <option value="RUN_ONCE">Missed: run once</option>
            <option value="SKIP">Missed: skip</option>
            <option value="CATCH_UP_LIMITED">Missed: catch up (max 3)</option>
          </select>
          <button disabled={busy || !name} onClick={() => void create()} className="rounded bg-emerald-700 px-3 py-1.5 text-sm text-white disabled:opacity-50">Create schedule</button>
        </div>
        <p className="mt-2 text-xs text-slate-500">Scan schedules snapshot the approved assessment&apos;s profile. Approval-required or prohibited profiles are refused. Intel sync records an honest not-configured outcome until a data source is configured.</p>
      </Card>
      {state === "loading" ? <p className="text-slate-400">Loading…</p> : null}
      {state === "error" ? <EmptyState title="Could not load" body={error} /> : null}
      {state === "ready" ? (
        <>
          <Card>
            <h3 className="mb-2 font-medium text-slate-100">Schedules</h3>
            {schedules.length === 0 ? <EmptyState title="No schedules" body="Nothing is being monitored continuously yet." /> : (
              <table className="w-full text-left text-sm text-slate-300">
                <thead><tr className="text-slate-500"><th className="py-1">Name</th><th>Kind</th><th>Profile</th><th>Expression</th><th>Next run</th><th>Last</th><th>State</th><th></th></tr></thead>
                <tbody>
                  {schedules.map((s) => (
                    <tr key={s.id} className="border-t border-slate-800">
                      <td className="py-1.5 text-slate-100">{s.name}</td>
                      <td><Badge>{s.kind}</Badge></td>
                      <td>{s.profile ?? "—"}</td>
                      <td className="font-mono text-xs">{s.expression} ({s.timezone})</td>
                      <td>{new Date(s.nextRunAt).toLocaleString()}</td>
                      <td>{s.lastStatus ?? "—"}</td>
                      <td>{!s.enabled ? "disabled" : s.paused ? "paused" : "active"}</td>
                      <td className="space-x-1 whitespace-nowrap">
                        <button disabled={busy} onClick={() => void act(s.id, "run")} className="rounded bg-slate-800 px-2 py-1 text-xs">Run now</button>
                        {s.paused
                          ? <button disabled={busy} onClick={() => void act(s.id, "resume")} className="rounded bg-slate-800 px-2 py-1 text-xs">Resume</button>
                          : <button disabled={busy} onClick={() => void act(s.id, "pause")} className="rounded bg-slate-800 px-2 py-1 text-xs">Pause</button>}
                        <button disabled={busy} onClick={() => void act(s.id, "delete")} className="rounded bg-slate-800 px-2 py-1 text-xs">Delete</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>
          <Card>
            <h3 className="mb-2 font-medium text-slate-100">Run history</h3>
            {runs.length === 0 ? <EmptyState title="No runs yet" body="Materialized (and refused) runs will appear here with their reason codes." /> : (
              <ul className="space-y-1 text-sm text-slate-300">
                {runs.slice(0, 50).map((r) => (
                  <li key={r.id} className="flex flex-wrap items-center gap-2">
                    <Badge>{r.status}</Badge>
                    <span className="text-slate-500">{new Date(r.scheduledFor).toLocaleString()}</span>
                    {r.reasonCode ? <span className="font-mono text-xs text-amber-300">{r.reasonCode}</span> : null}
                    <span className="text-slate-400">{r.reason ?? ""}</span>
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
