"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Directory drift (Prompt 15 §98): changes between consecutive
 * snapshots — new privileged members, new trusts, GPO and delegation
 * changes, risky ACLs, template changes. Drift events are REVIEW
 * SIGNALS: they are never classified malicious automatically (§80).
 */
interface DriftData {
  items: Array<{ id: string; kind: string; objectRef?: string | null; detail: string; detectedAt: string }>;
}

export default function Page() {
  const [data, setData] = useState<DriftData>({ items: [] });
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      setData(await apiFetch<DriftData>("/ad/drift"));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not load drift events.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Directory Drift" title="Directory Drift" body="Snapshot-to-snapshot changes for analyst review. A drift event is a signal to review — never an automatic malicious verdict." />
      {error && <p className="text-sm text-red-400">{error}</p>}
      <Card>
        {data.items.length === 0 ? (
          <EmptyState title="No drift events" body="Drift appears once two snapshots of the same domain exist." />
        ) : (
          <ul className="text-sm space-y-2">
            {data.items.map((d) => (
              <li key={d.id} className="border-b border-slate-800 pb-2">
                <Badge>{d.kind}</Badge>{" "}
                <span className="text-slate-300">{d.objectRef ?? ""}</span>
                <span className="block text-slate-400">{d.detail}</span>
                <span className="block text-xs text-slate-500">{new Date(d.detectedAt).toLocaleString()}</span>
              </li>
            ))}
          </ul>
        )}
      </Card>
    </div>
  );
}
