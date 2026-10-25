"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@zerosweep/ui";

/**
 * Queue admin (Prompt 38 §198): backlog per governed queue, failed-job
 * inspection, and bounded operator actions. Retry is limited server-
 * side to IDs-only job kinds; cancelling an active (leased) job is
 * refused server-side. Every action is audited (§204).
 */
interface QueueRow { name: string; waiting: number; active: number; completed: number; failed: number; delayed: number; paused: boolean; oldestWaitingAgeMs: number | null }
interface FailedJob { id: string; kind: string; attemptsMade: number; failedReason: string }

export default function Page() {
  const [queues, setQueues] = useState<QueueRow[]>([]);
  const [selected, setSelected] = useState("");
  const [failed, setFailed] = useState<FailedJob[]>([]);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const load = useCallback(async () => {
    try {
      const data = await apiFetch<{ items: QueueRow[] }>("/platform/queues");
      setQueues(data.items ?? []);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const inspect = async (name: string) => {
    setSelected(name);
    setNotice("");
    try {
      const data = await apiFetch<{ items: FailedJob[] }>(`/platform/queues/${encodeURIComponent(name)}/failed`);
      setFailed(data.items ?? []);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not load failed jobs.");
    }
  };

  const act = async (jobId: string, action: "retry" | "cancel") => {
    try {
      await apiFetch(`/platform/queues/${encodeURIComponent(selected)}/jobs/${encodeURIComponent(jobId)}/${action}`, { method: "POST", body: JSON.stringify({}) });
      setNotice(`${action} applied to job ${jobId}`);
      await inspect(selected);
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : `Could not ${action} the job.`);
    }
  };

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Platform Operations" title="Queues" body="Backlog and failed jobs across the governed queues. Retries re-run the worker's full authorization and scope gates — the admin plane never bypasses them." />
      {error && <p className="rounded bg-red-950/60 px-3 py-2 text-sm text-red-300">{error}</p>}
      {notice && <p className="rounded bg-emerald-950/60 px-3 py-2 text-sm text-emerald-300">{notice}</p>}
      <Card>
        {queues.length === 0 && <EmptyState title="No queue data" body="Queue state appears here once the API can reach Redis." />}
        <div className="divide-y divide-slate-800">
          {queues.map((q) => (
            <div key={q.name} className="flex flex-wrap items-center gap-3 py-2 text-sm">
              <button className="text-sky-400 underline" onClick={() => void inspect(q.name)}>{q.name}</button>
              <span className="text-slate-400">waiting {q.waiting} · active {q.active} · failed {q.failed} · delayed {q.delayed}</span>
              {q.paused && <Badge>paused</Badge>}
              <span className="ml-auto text-xs text-slate-500">
                {q.oldestWaitingAgeMs === null ? "" : `oldest waiting ${Math.round(q.oldestWaitingAgeMs / 1000)}s`}
              </span>
            </div>
          ))}
        </div>
      </Card>
      {selected && (
        <Card>
          <p className="text-xs uppercase text-slate-500">Failed jobs · {selected}</p>
          <div className="mt-2 divide-y divide-slate-800">
            {failed.map((j) => (
              <div key={j.id} className="flex flex-wrap items-center gap-3 py-2 text-sm">
                <span className="text-slate-200">{j.kind}</span>
                <span className="text-slate-400">job {j.id} · attempts {j.attemptsMade}</span>
                <span className="text-slate-500">{j.failedReason}</span>
                <span className="ml-auto flex gap-2">
                  <button className="rounded bg-slate-800 px-2 py-1 text-xs text-slate-200" onClick={() => void act(j.id, "retry")}>Retry</button>
                  <button className="rounded bg-slate-800 px-2 py-1 text-xs text-slate-200" onClick={() => void act(j.id, "cancel")}>Cancel</button>
                </span>
              </div>
            ))}
            {failed.length === 0 && <p className="py-2 text-sm text-slate-400">No failed jobs in this queue.</p>}
          </div>
        </Card>
      )}
    </div>
  );
}
