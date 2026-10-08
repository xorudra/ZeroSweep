"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Card, EmptyState, StatCard } from "@dsrclone/ui";

/** Cloud analytics (Prompt 27 §92) — from cloud finding extension data recorded by the cloud modules. */
interface KeyCount { key: string | null; count: number }
interface Cloud {
  sources: string[]; accounts: number; totalCloudFindings: number;
  byProvider: KeyCount[]; byClass: KeyCount[];
  publicResources: number; iamRisks: number; encryptionGaps: number; loggingGaps: number;
  criticalMisconfigurations: number;
}

export default function Page() {
  const [data, setData] = useState<Cloud | null>(null);
  const [error, setError] = useState("");
  const load = useCallback(async () => {
    try { setData(await apiFetch<Cloud>("/analytics/cloud")); }
    catch (e) { setError(e instanceof ApiError ? e.message : "Could not reach the API."); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Cloud Analytics" title="Cloud" body="Cloud posture analytics over findings that carry cloud extension data (provider, account, class). Accounts without posture data simply do not appear." />
      {error && <p className="rounded bg-red-950/60 px-3 py-2 text-sm text-red-300">{error}</p>}
      {!data ? <EmptyState title="Loading cloud analytics…" body="" /> : data.totalCloudFindings === 0 ? (
        <EmptyState title="No cloud findings recorded" body="Run cloud posture assessments (Prompt 14/34) to populate cloud analytics." />
      ) : (
        <>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <StatCard label="Cloud accounts" value={data.accounts} />
            <StatCard label="Cloud findings" value={data.totalCloudFindings} />
            <StatCard label="Public resources" value={data.publicResources} />
            <StatCard label="Critical misconfigurations" value={data.criticalMisconfigurations} />
          </div>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <Card title="By provider">
              <ul className="space-y-1 text-sm">{data.byProvider.map((r) => <li key={String(r.key)} className="flex justify-between"><span>{r.key}</span><span>{r.count}</span></li>)}</ul>
            </Card>
            <Card title="By class">
              <ul className="space-y-1 text-sm">{data.byClass.map((r) => <li key={String(r.key)} className="flex justify-between"><span>{r.key}</span><span>{r.count}</span></li>)}</ul>
            </Card>
            <Card title="Risk themes">
              <ul className="space-y-1 text-sm">
                <li className="flex justify-between"><span>IAM risks</span><span>{data.iamRisks}</span></li>
                <li className="flex justify-between"><span>Encryption gaps</span><span>{data.encryptionGaps}</span></li>
                <li className="flex justify-between"><span>Logging gaps</span><span>{data.loggingGaps}</span></li>
              </ul>
            </Card>
          </div>
          <p className="text-xs text-slate-500">Sources: {data.sources.join(", ")}</p>
        </>
      )}
    </div>
  );
}
