"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@zerosweep/ui";

/**
 * Network exposure (Prompt 14 §82) + drift (§63). Exposure comes from
 * configuration evidence (security groups, NSGs, firewall rules,
 * public IPs) — world-open sensitive ports are findings; standard web
 * ports are not. Drift events are observations, never automatic
 * malicious verdicts (§64).
 */
interface ExposureData {
  resources: Array<{ id: string; provider: string; resourceType: string; providerResourceId: string; name: string; region?: string | null; exposure: string }>;
  exposureFindings: Array<{ id: string; title: string; severity: string; ruleId?: string | null; providerResourceId?: string | null }>;
}
interface DriftRow { id: string; kind: string; state?: string | null; resourceRef?: string | null; detail: string; detectedAt?: string }

export default function Page() {
  const [exposure, setExposure] = useState<ExposureData>({ resources: [], exposureFindings: [] });
  const [drift, setDrift] = useState<DriftRow[]>([]);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const [exp, dr] = await Promise.all([
        apiFetch<ExposureData>("/cloud/exposure"),
        apiFetch<{ items: DriftRow[] }>("/cloud/drift"),
      ]);
      setExposure(exp);
      setDrift(dr.items ?? []);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Cloud Exposure" title="Network Exposure & Drift" body="Publicly exposed resources and the exposure findings behind them, plus inventory drift between snapshots. Nothing here was probed over the network — every row is configuration evidence from the provider inventory." />
      {error && <p className="rounded bg-red-950/60 px-3 py-2 text-sm text-red-300">{error}</p>}
      <Card>
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Exposed resources</h2>
        {exposure.resources.length === 0 && <EmptyState title="No public exposure observed" body="No resource configuration proved internet reachability in the latest inventory." />}
        <div className="divide-y divide-slate-800">
          {exposure.resources.map((r) => (
            <div key={r.id} className="flex flex-wrap items-center gap-3 py-2 text-sm">
              <Link className="text-cyan-300 hover:underline" href={`/cloud-security/resources/${r.id}`}>{r.name}</Link>
              <Badge>{r.provider}</Badge>
              <span className="font-mono text-xs text-slate-400">{r.resourceType}</span>
              <span className="text-slate-400">{r.region ?? "global"}</span>
              <Badge>{r.exposure}</Badge>
            </div>
          ))}
        </div>
      </Card>
      <Card>
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Exposure findings</h2>
        {exposure.exposureFindings.length === 0 && <p className="text-sm text-slate-500">No PUBLIC_EXPOSURE findings.</p>}
        <div className="divide-y divide-slate-800">
          {exposure.exposureFindings.map((f) => (
            <div key={f.id} className="flex flex-wrap items-center gap-3 py-2 text-sm">
              <Badge>{f.severity}</Badge>
              <span className="text-slate-200">{f.title}</span>
              <span className="ml-auto font-mono text-xs text-slate-500">{f.ruleId ?? ""}</span>
            </div>
          ))}
        </div>
      </Card>
      <Card>
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Drift events (§63/§64)</h2>
        {drift.length === 0 && <p className="text-sm text-slate-500">No drift recorded — drift appears when a later snapshot differs from the previous one, or IaC disagrees with the live estate.</p>}
        <div className="divide-y divide-slate-800">
          {drift.map((d) => (
            <div key={d.id} className="flex flex-wrap items-center gap-3 py-2 text-sm">
              <Badge>{d.kind}</Badge>
              {d.state && <Badge>{d.state}</Badge>}
              <span className="text-slate-300">{d.resourceRef ?? ""}</span>
              <span className="max-w-md truncate text-slate-500">{d.detail}</span>
              <span className="ml-auto text-xs text-slate-500">{d.detectedAt ? new Date(d.detectedAt).toLocaleString() : ""}</span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
