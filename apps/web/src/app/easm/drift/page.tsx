"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { EmptyState } from "@dsrclone/ui";

/**
 * Exposure drift (Prompt 29 §102). Drift compares discovery against
 * immutable baselines. A disappeared asset is never deleted in one
 * run — disappearance requires repeated confirmation.
 */
interface Drift {
  id: string; assetIdentity: string; type: string; severity: string; status: string;
  detectedAt: string; before: unknown; after: unknown;
}

export default function Page() {
  const [items, setItems] = useState<Drift[]>([]);
  const [error, setError] = useState("");
  const [severity, setSeverity] = useState("");

  const load = useCallback(async () => {
    try {
      const params = new URLSearchParams();
      if (severity) params.set("severity", severity);
      const res = await apiFetch<{ items: Drift[] }>(`/easm/drift?${params.toString()}`);
      setItems(res.items);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, [severity]);

  useEffect(() => { void load(); }, [load]);

  const ack = async (id: string) => {
    try {
      await apiFetch(`/easm/drift/${id}/acknowledge`, { method: "POST", body: JSON.stringify({}) });
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Acknowledge failed.");
    }
  };

  return (
    <main>
      <PageHeader eyebrow="EASM" title="Exposure Drift" />
      <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
        <option value="">All severities</option>
        <option value="CRITICAL">Critical</option>
        <option value="HIGH">High</option>
        <option value="MEDIUM">Medium</option>
        <option value="LOW">Low</option>
      </select>
      {error ? <p role="alert">{error}</p> : null}
      {items.length === 0 ? <EmptyState title="No drift events match." body="" /> : (
        <table>
          <thead><tr><th>Asset</th><th>Change</th><th>Severity</th><th>Status</th><th>Detected</th><th>Before → After</th><th /></tr></thead>
          <tbody>
            {items.map((d) => (
              <tr key={d.id}>
                <td>{d.assetIdentity}</td>
                <td>{d.type}</td>
                <td>{d.severity}</td>
                <td>{d.status}</td>
                <td>{new Date(d.detectedAt).toLocaleString()}</td>
                <td><code>{JSON.stringify(d.before) ?? "—"}</code> → <code>{JSON.stringify(d.after) ?? "—"}</code></td>
                <td>{d.status !== "ACKNOWLEDGED" && d.status !== "CONFIRMED" ? <button onClick={() => ack(d.id)}>Acknowledge</button> : null}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </main>
  );
}
