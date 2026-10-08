"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Worker admin (Prompt 38 §199): the registered worker pools with
 * capabilities, versions and heartbeat-derived status. Status is
 * derived from heartbeat age server-side (§48) — a worker that stops
 * beating shows STALE, then OFFLINE; it is never shown healthy on its
 * own say-so.
 */
interface WorkerRow {
  workerId: string; hostname: string; version: string; workerType: string;
  capabilities: unknown; activeJobs: number; status: string; heartbeatAgeMs: number; lastHeartbeat: string;
}

export default function Page() {
  const [items, setItems] = useState<WorkerRow[]>([]);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const data = await apiFetch<{ items: WorkerRow[] }>("/platform/workers");
      setItems(data.items ?? []);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Platform Operations" title="Workers" body="Scanner and background worker pools. Scanner workers are isolated from the control plane (§50); privileged tools run only on the dedicated privileged worker class (§51)." />
      {error && <p className="rounded bg-red-950/60 px-3 py-2 text-sm text-red-300">{error}</p>}
      <Card>
        {items.length === 0 && <EmptyState title="No workers registered" body="Workers appear here after their first registration heartbeat." />}
        <div className="divide-y divide-slate-800">
          {items.map((w) => (
            <div key={w.workerId} className="flex flex-wrap items-center gap-3 py-2 text-sm">
              <Badge>{w.status}</Badge>
              <span className="text-slate-200">{w.workerId}</span>
              <span className="text-slate-400">{w.workerType} · {w.hostname} · v{w.version}</span>
              <span className="text-slate-500">
                capabilities {Array.isArray(w.capabilities) ? w.capabilities.join(", ") : "—"} · active jobs {w.activeJobs}
              </span>
              <span className="ml-auto text-xs text-slate-500">heartbeat {Math.round(w.heartbeatAgeMs / 1000)}s ago</span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
