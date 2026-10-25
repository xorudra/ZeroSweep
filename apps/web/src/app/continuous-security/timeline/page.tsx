"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@zerosweep/ui";

/**
 * Security timeline (Prompt 22 §79): one chronological stream of
 * attack-surface changes, finding/risk drift and schedule runs.
 */
interface TimelineItem { at: string; kind: string; type: string; detail: string; ref: string }

export default function Page() {
  const [items, setItems] = useState<TimelineItem[]>([]);
  const [state, setState] = useState<"loading" | "error" | "ready">("loading");
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const out = await apiFetch<{ items: TimelineItem[] }>("/posture/timeline");
      setItems(out.items ?? []);
      setState("ready");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "failed to load timeline");
      setState("error");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Continuous Security" title="Security Timeline" body="Every detected change and every scheduled run, in order." />
      {state === "loading" ? <p className="text-slate-400">Loading…</p> : null}
      {state === "error" ? <EmptyState title="Could not load" body={error} /> : null}
      {state === "ready" ? (
        <Card>
          {items.length === 0 ? <EmptyState title="Nothing yet" body="Drift events and schedule runs will stream in here." /> : (
            <ul className="space-y-2 text-sm text-slate-300">
              {items.map((item, i) => (
                <li key={`${item.at}-${i}`} className="flex flex-wrap items-center gap-2 border-b border-slate-800 pb-2">
                  <span className="text-slate-500">{new Date(item.at).toLocaleString()}</span>
                  <Badge>{item.kind}</Badge>
                  <span className="text-slate-100">{item.type}</span>
                  <span className="text-slate-400">{item.detail}</span>
                </li>
              ))}
            </ul>
          )}
        </Card>
      ) : null}
    </div>
  );
}
