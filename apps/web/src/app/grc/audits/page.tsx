"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/** Audit dashboard (Prompt 26 §80): engagements, evidence requests,
 *  open audit findings, package status. Audit findings are separate
 *  from technical findings; packages are CONFIDENTIAL and sealed with
 *  an integrity manifest. */
interface AuditRow {
  id: string; type: string; status: string; auditorRef: string;
  openRequests: number; openFindings: number; packageCount: number; createdAt: string;
}

export default function Page() {
  const [items, setItems] = useState<AuditRow[]>([]);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const data = await apiFetch<{ items: AuditRow[] }>("/grc/audits");
      setItems(data.items ?? []);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="GRC · Audits" title="Audit Management" body="Engagements, evidence requests and sealed evidence packages. Auditor access is explicit-share and time-limited; packages verify against their hash manifest." />
      {error && <p className="rounded bg-red-950/60 px-3 py-2 text-sm text-red-300">{error}</p>}
      <Card>
        {items.length === 0 ? (
          <EmptyState title="No audit engagements" body="Create an engagement via POST /api/v1/grc/audits to start evidence collection." />
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-slate-400">
                <th className="py-1">Type</th><th>Auditor / reviewer</th><th>Status</th>
                <th>Open requests</th><th>Open findings</th><th>Packages</th>
              </tr>
            </thead>
            <tbody>
              {items.map((a) => (
                <tr key={a.id} className="border-t border-slate-800">
                  <td className="py-2 pr-2">{a.type}</td>
                  <td className="pr-2">{a.auditorRef || "—"}</td>
                  <td className="pr-2"><Badge>{a.status}</Badge></td>
                  <td className="pr-2">{a.openRequests}</td>
                  <td className="pr-2">{a.openFindings}</td>
                  <td className="pr-2">{a.packageCount}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
