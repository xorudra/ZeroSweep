"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@zerosweep/ui";

/** Evidence dashboard (Prompt 26 §81): source, classification,
 *  freshness, integrity. Evidence is snapshot-based and hashed at
 *  collection; restricted evidence content is leads-only. */
interface EvidenceDashboard {
  total: number;
  byStatus: Record<string, number>;
  byClassification: Record<string, number>;
  items: Array<{
    id: string; sourceType: string; sourceId: string; classification: string;
    hash: string; collectedAt: string; reviewStatus: string;
  }>;
}

export default function Page() {
  const [data, setData] = useState<EvidenceDashboard | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      setData(await apiFetch<EvidenceDashboard>("/grc/dashboard/evidence"));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="GRC · Evidence" title="Compliance Evidence" body="Snapshot-based, hash-sealed evidence. Freshness is derived per control policy — MFA evidence ages in days, backup evidence in hours-to-days, DR evidence in months." />
      {error && <p className="rounded bg-red-950/60 px-3 py-2 text-sm text-red-300">{error}</p>}
      {!data ? (
        <EmptyState title="Loading evidence…" body="" />
      ) : (
        <>
          <div className="grid gap-4 md:grid-cols-2">
            <Card>
              <p className="text-xs uppercase text-slate-400">By freshness</p>
              <ul className="mt-2 space-y-1 text-sm">
                {Object.entries(data.byStatus).map(([k, v]) => (
                  <li key={k} className="flex justify-between"><span>{k}</span><Badge>{String(v)}</Badge></li>
                ))}
              </ul>
            </Card>
            <Card>
              <p className="text-xs uppercase text-slate-400">By classification</p>
              <ul className="mt-2 space-y-1 text-sm">
                {Object.entries(data.byClassification).map(([k, v]) => (
                  <li key={k} className="flex justify-between"><span>{k}</span><Badge>{String(v)}</Badge></li>
                ))}
              </ul>
            </Card>
          </div>
          <Card>
            <h3 className="mb-3 font-medium">Recent evidence</h3>
            {data.items.length === 0 ? (
              <EmptyState title="No evidence collected" body="Evidence is collected from platform state or uploaded manually under the file-security policy." />
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-slate-400">
                    <th className="py-1">Source</th><th>Classification</th><th>Review</th><th>Collected</th><th>Hash</th>
                  </tr>
                </thead>
                <tbody>
                  {data.items.map((e) => (
                    <tr key={e.id} className="border-t border-slate-800">
                      <td className="py-2 pr-2">{e.sourceType} · {e.sourceId}</td>
                      <td className="pr-2">{e.classification}</td>
                      <td className="pr-2">{e.reviewStatus}</td>
                      <td className="pr-2">{new Date(e.collectedAt).toLocaleString()}</td>
                      <td className="pr-2 font-mono text-xs">{e.hash.slice(0, 12)}…</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
