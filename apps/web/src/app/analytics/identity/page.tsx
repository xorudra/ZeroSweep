"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Card, EmptyState, StatCard } from "@zerosweep/ui";

/** Identity analytics (Prompt 27 §93) — MFA coverage, SSO, privileged identities, keys and access reviews (organization-scoped, Prompt 23 records). */
interface Identity {
  sources: string[]; members: number; mfaCoverage: number | null; mfaEnrolledUsers: number;
  ssoProviders: number; ssoEnabled: number; privilegedIdentities: number; privilegedWithoutMfa: number;
  apiKeys: number; serviceAccounts: number; pendingAccessReviews: number;
}

export default function Page() {
  const [data, setData] = useState<Identity | null>(null);
  const [error, setError] = useState("");
  const load = useCallback(async () => {
    try { setData(await apiFetch<Identity>("/analytics/identity")); }
    catch (e) { setError(e instanceof ApiError ? e.message : "Could not reach the API."); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Identity Analytics" title="Identity" body="MFA coverage, SSO posture, privileged identities and key inventory computed from the enterprise identity records." />
      {error && <p className="rounded bg-red-950/60 px-3 py-2 text-sm text-red-300">{error}</p>}
      {!data ? <EmptyState title="Loading identity analytics…" body="" /> : (
        <>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <StatCard label="Members" value={data.members} />
            <StatCard label="MFA coverage" value={data.mfaCoverage === null ? "—" : `${(data.mfaCoverage * 100).toFixed(0)}%`} hint={`${data.mfaEnrolledUsers} enrolled`} />
            <StatCard label="Privileged without MFA" value={data.privilegedWithoutMfa} hint={`${data.privilegedIdentities} privileged identities`} />
            <StatCard label="Pending access reviews" value={data.pendingAccessReviews} />
          </div>
          <Card title="Identity surface">
            <ul className="space-y-1 text-sm">
              <li className="flex justify-between"><span>SSO providers</span><span>{data.ssoProviders} ({data.ssoEnabled} enabled)</span></li>
              <li className="flex justify-between"><span>Active API keys</span><span>{data.apiKeys}</span></li>
              <li className="flex justify-between"><span>Service accounts</span><span>{data.serviceAccounts}</span></li>
            </ul>
          </Card>
          <p className="text-xs text-slate-500">Sources: {data.sources.join(", ")}</p>
        </>
      )}
    </div>
  );
}
