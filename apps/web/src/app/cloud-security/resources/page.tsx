"use client";

import { Suspense, useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useSearchParams } from "next/navigation";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Cloud resources (Prompt 14 §79): the normalized multi-cloud
 * inventory — resources are assets with provider / region / service
 * identity. Metadata only (§13): no object contents, secret values or
 * key material exist anywhere in this inventory.
 */
interface ResourceRow {
  id: string; cloudAccountId: string; provider: string; resourceType: string;
  providerResourceId: string; name: string; region?: string | null;
  exposure: string; status: string; scopeStatus: string; sources: string[];
  tags: Record<string, string>;
}

const inputCls = "rounded bg-slate-900 px-2 py-1.5 text-sm text-slate-200 border border-slate-700";

function ResourcesInner() {
  const searchParams = useSearchParams();
  const accountId = searchParams.get("accountId") ?? "";
  const [items, setItems] = useState<ResourceRow[]>([]);
  const [provider, setProvider] = useState("");
  const [exposure, setExposure] = useState("");
  const [search, setSearch] = useState("");
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const qs = new URLSearchParams();
      if (accountId) qs.set("accountId", accountId);
      if (provider) qs.set("provider", provider);
      if (exposure) qs.set("exposure", exposure);
      if (search) qs.set("search", search);
      const data = await apiFetch<{ items: ResourceRow[] }>(`/cloud/resources${qs.toString() ? `?${qs}` : ""}`);
      setItems(data.items ?? []);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, [accountId, provider, exposure, search]);

  useEffect(() => { void load(); }, [load]);

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Cloud Inventory" title="Cloud Resources" body="Normalized resources from read-only provider inventory. Exposure is classified from configuration evidence only — PUBLIC means the configuration itself proves internet reachability." />
      {error && <p className="rounded bg-red-950/60 px-3 py-2 text-sm text-red-300">{error}</p>}
      <Card>
        <div className="mb-3 flex flex-wrap items-center gap-2">
          <label className="text-xs text-slate-400">Provider
            <select className={`ml-2 ${inputCls}`} value={provider} onChange={(e) => setProvider(e.target.value)}>
              <option value="">All</option><option value="AWS">AWS</option><option value="AZURE">Azure</option><option value="GCP">GCP</option>
            </select>
          </label>
          <label className="text-xs text-slate-400">Exposure
            <select className={`ml-2 ${inputCls}`} value={exposure} onChange={(e) => setExposure(e.target.value)}>
              <option value="">All</option><option value="PUBLIC">PUBLIC</option><option value="INTERNET_REACHABLE_POSSIBLE">POSSIBLE</option><option value="PRIVATE">PRIVATE</option><option value="UNKNOWN">UNKNOWN</option>
            </select>
          </label>
          <input className={inputCls} placeholder="Search by name…" value={search} onChange={(e) => setSearch(e.target.value)} />
          <span className="ml-auto text-xs text-slate-500">{items.length} resources</span>
        </div>
        {items.length === 0 && <EmptyState title="No resources inventoried" body="Run a cloud inventory or baseline scan on a registered account." />}
        <div className="divide-y divide-slate-800">
          {items.map((r) => (
            <div key={r.id} className="flex flex-wrap items-center gap-3 py-2 text-sm">
              <Link className="text-cyan-300 hover:underline" href={`/cloud-security/resources/${r.id}`}>{r.name}</Link>
              <Badge>{r.provider}</Badge>
              <span className="font-mono text-xs text-slate-400">{r.resourceType}</span>
              <span className="text-slate-400">{r.region ?? "global"}</span>
              <Badge>{r.exposure}</Badge>
              {r.scopeStatus !== "IN_SCOPE" && <Badge>{r.scopeStatus}</Badge>}
              {r.status !== "ACTIVE" && <Badge>{r.status}</Badge>}
              <span className="ml-auto font-mono text-xs text-slate-500">{(r.sources ?? []).join(", ")}</span>
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
      <ResourcesInner />
    </Suspense>
  );
}
