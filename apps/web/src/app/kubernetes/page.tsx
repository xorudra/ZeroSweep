"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Kubernetes security (Prompt 13 §83). Clusters are registered by
 * reference: an API-server reference name plus a credential REFERENCE —
 * never a kubeconfig or token. Assessment is read-only posture over
 * inventory metadata; workload secret values are never retrieved.
 */
interface ClusterRow {
  id: string; name: string; provider?: string | null; version?: string | null;
  apiServerReference: string; credentialReference?: string | null;
  workloads: number; lastAssessmentAt?: string | null;
}
interface WorkloadRow {
  id: string; clusterId: string; kind: string; namespace: string; name: string;
  exposure: string; serviceAccount?: string | null;
  images: Array<{ reference?: string; digest?: string }>;
}

const inputCls = "rounded bg-slate-900 px-2 py-1.5 text-sm text-slate-200 border border-slate-700";
const PROFILES = ["KUBERNETES_BASELINE", "KUBERNETES_COMPREHENSIVE", "CLOUD_NATIVE_FULL"] as const;

export default function Page() {
  const [clusters, setClusters] = useState<ClusterRow[]>([]);
  const [workloads, setWorkloads] = useState<WorkloadRow[]>([]);
  const [state, setState] = useState<"loading" | "error" | "ready">("loading");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState<string | null>(null);
  const [profile, setProfile] = useState<string>("KUBERNETES_BASELINE");
  const [name, setName] = useState("");
  const [apiRef, setApiRef] = useState("");
  const [credRef, setCredRef] = useState("");

  const load = useCallback(async () => {
    try {
      const [clu, wk] = await Promise.all([
        apiFetch<{ items: ClusterRow[] }>("/kubernetes/clusters"),
        apiFetch<{ items: WorkloadRow[] }>("/kubernetes/workloads"),
      ]);
      setClusters(clu.items ?? []);
      setWorkloads(wk.items ?? []);
      setState("ready");
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
      setState("error");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  async function createCluster() {
    setBusy("cluster");
    try {
      await apiFetch("/kubernetes/clusters", {
        method: "POST",
        body: JSON.stringify({
          name, apiServerReference: apiRef,
          ...(credRef ? { credentialReference: credRef } : {}),
        }),
      });
      setName(""); setApiRef(""); setCredRef("");
      setNotice("Cluster registered by reference. Verify its target registration, then start a posture scan.");
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Cluster registration failed.");
    } finally { setBusy(null); }
  }

  async function scan(id: string) {
    setBusy(id);
    try {
      const out = await apiFetch<{ scanId?: string }>(`/kubernetes/clusters/${id}/scan`, { method: "POST", body: JSON.stringify({ profile }) });
      setNotice(`Posture scan started (${out.scanId ?? "queued"}) with profile ${profile}.`);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Scan start failed — the cluster target must be VERIFIED first.");
    } finally { setBusy(null); }
  }

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Kubernetes Security" title="Kubernetes" body="Read-only posture assessment over inventory metadata. ZeroSweep never applies manifests, never execs into pods, and never retrieves secret values." />
      {error && <p className="rounded bg-red-950/60 px-3 py-2 text-sm text-red-300">{error}</p>}
      {notice && <p className="rounded bg-emerald-950/60 px-3 py-2 text-sm text-emerald-300">{notice}</p>}

      <Card>
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Register cluster (references only)</h2>
        <div className="flex flex-wrap items-end gap-2">
          <label className="flex flex-col gap-1 text-xs text-slate-400">Cluster name
            <input className={inputCls} placeholder="prod-eu" value={name} onChange={(e) => setName(e.target.value)} />
          </label>
          <label className="flex flex-col gap-1 text-xs text-slate-400">API server reference
            <input className={`${inputCls} w-64`} placeholder="prod-eu-apiserver" value={apiRef} onChange={(e) => setApiRef(e.target.value)} />
          </label>
          <label className="flex flex-col gap-1 text-xs text-slate-400">Credential reference (name only)
            <input className={inputCls} placeholder="prod-eu-kubeconfig" value={credRef} onChange={(e) => setCredRef(e.target.value)} />
          </label>
          <button className="rounded bg-cyan-700 px-3 py-1.5 text-sm text-white disabled:opacity-50" disabled={busy === "cluster" || !name || !apiRef} onClick={() => void createCluster()}>Register</button>
          <label className="flex flex-col gap-1 text-xs text-slate-400">Scan profile
            <select className={inputCls} value={profile} onChange={(e) => setProfile(e.target.value)}>
              {PROFILES.map((p) => <option key={p} value={p}>{p}</option>)}
            </select>
          </label>
        </div>
        <p className="mt-2 text-xs text-slate-500">Least privilege by design: the registered service account is read-only and never cluster-admin. Example: Rudra registers <span className="font-mono">prod-eu</span> with credential reference <span className="font-mono">prod-eu-kubeconfig</span> — the credential itself never enters ZeroSweep.</p>
      </Card>

      <Card>
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Clusters</h2>
        {state === "loading" && <p className="text-sm text-slate-400">Loading…</p>}
        {state === "ready" && clusters.length === 0 && <EmptyState title="No clusters registered" body="Register a cluster connection above to inventory workloads and assess posture." />}
        <div className="divide-y divide-slate-800">
          {clusters.map((c) => (
            <div key={c.id} className="flex flex-wrap items-center gap-3 py-2 text-sm">
              <Link className="text-cyan-300 hover:underline" href={`/kubernetes/clusters/${c.id}`}>{c.name}</Link>
              <span className="font-mono text-slate-400">{c.apiServerReference}</span>
              {c.version && <Badge>k8s {c.version}</Badge>}
              <span className="text-slate-400">{c.workloads} workloads</span>
              <span className="text-slate-500">{c.credentialReference ? `credential: ${c.credentialReference} (reference)` : "no credential reference"}</span>
              <button className="ml-auto rounded bg-slate-800 px-2 py-1 text-xs text-slate-200 disabled:opacity-50" disabled={busy === c.id} onClick={() => void scan(c.id)}>Assess ({profile})</button>
            </div>
          ))}
        </div>
      </Card>

      <Card>
        <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Workloads (all clusters)</h2>
        {workloads.length === 0 && <p className="text-sm text-slate-500">No workload inventory yet — run a cluster inventory scan.</p>}
        <div className="divide-y divide-slate-800">
          {workloads.map((w) => (
            <div key={w.id} className="flex flex-wrap items-center gap-3 py-2 text-sm">
              <Badge>{w.kind}</Badge>
              <span className="text-slate-200">{w.namespace}/{w.name}</span>
              <span className="text-slate-400">{w.exposure}</span>
              <span className="font-mono text-xs text-slate-500">{(w.images ?? []).map((i) => i.reference ?? "").filter(Boolean).join(", ")}</span>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
