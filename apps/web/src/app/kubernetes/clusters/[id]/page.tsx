"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Cluster detail (Prompt 13 §86): connection references, workload
 * inventory with image identities, and posture entry points. Secret
 * values are never retrieved — the API exposes counts and metadata
 * only, and this page says so.
 */
interface ClusterDetail {
  id: string; name: string; provider?: string | null; version?: string | null;
  apiServerReference: string; credentialReference?: string | null;
  environment?: string | null; criticality?: string | null; secretValuesExposed: boolean;
  lastAssessmentAt?: string | null;
  workloads: Array<{
    id: string; kind: string; namespace: string; name: string;
    exposure: string; serviceAccount?: string | null;
    images: Array<{ reference?: string; digest?: string }>;
  }>;
}

export default function Page() {
  const params = useParams<{ id: string }>();
  const [cluster, setCluster] = useState<ClusterDetail | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      setCluster(await apiFetch<ClusterDetail>(`/kubernetes/clusters/${params.id}`));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not load the cluster.");
    }
  }, [params.id]);

  useEffect(() => { void load(); }, [load]);

  if (!cluster) {
    return <div className="p-6">{error ? <p className="text-sm text-red-300">{error}</p> : <p className="text-sm text-slate-400">Loading…</p>}</div>;
  }

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Kubernetes Cluster" title={cluster.name} body="Read-only cluster posture. Inventory is metadata only — secret values are never retrieved or displayed." />
      <Link className="text-sm text-cyan-300 hover:underline" href="/kubernetes">← All clusters</Link>
      {error && <p className="rounded bg-red-950/60 px-3 py-2 text-sm text-red-300">{error}</p>}

      <Card>
        <div className="flex flex-wrap gap-4 text-sm text-slate-300">
          <span>API server reference: <span className="font-mono">{cluster.apiServerReference}</span></span>
          <span>Credential: {cluster.credentialReference ? <span className="font-mono">{cluster.credentialReference}</span> : "—"} (reference only)</span>
          <span>Environment: {cluster.environment ?? "—"} · Criticality: {cluster.criticality ?? "—"}</span>
          {cluster.version && <span>Version: {cluster.version}</span>}
          <Badge>secret values exposed: {cluster.secretValuesExposed ? "YES" : "never"}</Badge>
        </div>
        <p className="mt-2 text-xs text-slate-500">Last assessment: {cluster.lastAssessmentAt ?? "never"}. The worker connects with a least-privilege read-only service account resolved by credential reference — the account name and credential never enter ZeroSweep.</p>
      </Card>

      <Card>
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Workloads</h2>
        {cluster.workloads.length === 0 && <EmptyState title="No inventory yet" body="Run a KUBERNETES_BASELINE scan from the Kubernetes page to inventory workloads." />}
        <div className="divide-y divide-slate-800">
          {cluster.workloads.map((w) => (
            <div key={w.id} className="flex flex-wrap items-center gap-3 py-2 text-sm">
              <Badge>{w.kind}</Badge>
              <span className="text-slate-200">{w.namespace}/{w.name}</span>
              <span className="text-slate-400">{w.exposure}</span>
              <span className="text-slate-500">sa: {w.serviceAccount ?? "default"}</span>
              <span className="font-mono text-xs text-slate-500">{(w.images ?? []).map((i) => i.digest ? `${i.reference ?? ""}@${i.digest.slice(0, 19)}…` : (i.reference ?? "")).join(", ")}</span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
