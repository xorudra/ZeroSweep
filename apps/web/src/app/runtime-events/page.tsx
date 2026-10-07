"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Runtime security (Prompt 13 §89): Falco-class runtime detections
 * ingested through the trusted path, validated and sanitized before
 * storage. A runtime event is a detection with posture context — it is
 * never presented as a vulnerability or as proof of exploitation.
 */
interface EventRow {
  id: string; clusterName?: string | null; node?: string | null;
  namespace?: string | null; pod?: string | null; container?: string | null;
  rule: string; priority: string; eventTime?: string; source: string;
}

export default function Page() {
  const [items, setItems] = useState<EventRow[]>([]);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const data = await apiFetch<{ items: EventRow[] }>("/runtime-events");
      setItems(data.items ?? []);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Runtime Security" title="Runtime Events" body="Runtime detections from container sensors (Falco-class), correlated with workload posture for triage context. Events are detections — not vulnerabilities, and never proof of exploitation." />
      {error && <p className="rounded bg-red-950/60 px-3 py-2 text-sm text-red-300">{error}</p>}
      <Card>
        {items.length === 0 && <EmptyState title="No runtime events" body="No sensor feed is configured on this deployment yet — events appear here once a Falco-class sensor forwards detections through the trusted ingestion path." />}
        <div className="divide-y divide-slate-800">
          {items.map((e) => (
            <div key={e.id} className="flex flex-wrap items-center gap-3 py-2 text-sm">
              <Badge>{e.priority}</Badge>
              <span className="text-slate-200">{e.rule}</span>
              <span className="text-slate-400">{e.clusterName ?? ""} {e.namespace ?? ""}/{e.pod ?? ""}</span>
              <span className="text-slate-500">{e.container ?? ""} · {e.node ?? ""}</span>
              <span className="ml-auto text-xs text-slate-500">{e.eventTime ?? ""} · {e.source}</span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
