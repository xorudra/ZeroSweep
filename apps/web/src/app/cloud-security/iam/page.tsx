"use client";

import { Suspense, useCallback, useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@zerosweep/ui";

/**
 * Cloud IAM dashboard (Prompt 14 §81). Identities and the privilege
 * FACTS behind each verdict (parsed from policy documents as
 * untrusted input, under hard caps). Credential material is never
 * part of this view (§40): key AGE and status metadata only — secret
 * values are never retrieved by the platform.
 */
interface IdentityRow {
  id: string; cloudAccountId: string; provider: string; identityType: string;
  providerIdentityId: string; name: string; privileged: boolean;
  privilegeEvidence?: Record<string, unknown> | null;
  mfaEnabled?: boolean | null; keyAgeDays?: number | null; lastUsedAt?: string | null;
}

function IamInner() {
  const searchParams = useSearchParams();
  const accountId = searchParams.get("accountId") ?? "";
  const [items, setItems] = useState<IdentityRow[]>([]);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const data = await apiFetch<{ items: IdentityRow[] }>(`/cloud/iam${accountId ? `?accountId=${accountId}` : ""}`);
      setItems(data.items ?? []);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, [accountId]);

  useEffect(() => { void load(); }, [load]);

  const privileged = items.filter((i) => i.privileged);

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Cloud IAM" title="IAM Analysis" body="Privileged identities first. A privilege verdict is evidence-backed (wildcard/admin policy facts, broad trust, provider role metadata) — identity alone is never the finding." />
      {error && <p className="rounded bg-red-950/60 px-3 py-2 text-sm text-red-300">{error}</p>}
      <div className="grid gap-4 md:grid-cols-3">
        <Card><p className="text-xs uppercase tracking-wide text-slate-400">Identities</p><p className="mt-1 text-2xl font-bold text-slate-50">{items.length}</p></Card>
        <Card><p className="text-xs uppercase tracking-wide text-slate-400">Privileged</p><p className="mt-1 text-2xl font-bold text-slate-50">{privileged.length}</p></Card>
        <Card><p className="text-xs uppercase tracking-wide text-slate-400">MFA gaps (users)</p><p className="mt-1 text-2xl font-bold text-slate-50">{items.filter((i) => i.identityType === "USER" && i.mfaEnabled === false).length}</p></Card>
      </div>
      <Card>
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Identities</h2>
        {items.length === 0 && <EmptyState title="No identities inventoried" body="Run a cloud inventory or IAM review scan on a registered account." />}
        <div className="divide-y divide-slate-800">
          {items.map((i) => (
            <div key={i.id} className="flex flex-wrap items-center gap-3 py-2 text-sm">
              <span className="text-slate-200">{i.name}</span>
              <Badge>{i.provider}</Badge>
              <Badge>{i.identityType}</Badge>
              {i.privileged && <Badge>PRIVILEGED</Badge>}
              {i.mfaEnabled === false && <span className="text-amber-300">MFA off</span>}
              {typeof i.keyAgeDays === "number" && <span className="text-slate-400">key age {i.keyAgeDays}d</span>}
              <span className="ml-auto max-w-md truncate font-mono text-xs text-slate-500">{i.providerIdentityId}</span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}

export default function Page() {
  return (
    <Suspense fallback={<p className="p-6 text-sm text-slate-400">Loading…</p>}>
      <IamInner />
    </Suspense>
  );
}
