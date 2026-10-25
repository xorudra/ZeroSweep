"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState, StatCard } from "@zerosweep/ui";

/**
 * Kubernetes Security dashboard (Prompt 34 §4/§130): RBAC posture,
 * workload risk, benchmarks, runtime signals, baselines (§98) and
 * coverage (§114). The kubeconfig is a secret REFERENCE, never
 * content (§72); Secret values are never inventoried (§83); no
 * workload action exists anywhere (§96).
 */
interface ClusterRow { id: string; name: string; provider: string; version?: string | null; apiServerReference: string; environment: string; credentialConfigured?: boolean }
interface RuntimeRow { id: string; rule: string; priority: string; namespace?: string | null; pod?: string | null; eventTime: string; correlation?: { confidence: string; socAlertLinked: boolean } | null }
interface CoverageRow { id: string; completion: string; workloadsCovered: number; rbacSubjects: number; gaps: Array<{ area: string; reason: string }> }
interface BaselineRow { id: string; version: number; hash: string; clusterId?: string | null }

const btnCls = "rounded bg-slate-800 px-2 py-1 text-xs text-slate-200 hover:bg-slate-700 disabled:opacity-50";

export default function Page() {
  const [clusters, setClusters] = useState<ClusterRow[]>([]);
  const [events, setEvents] = useState<RuntimeRow[]>([]);
  const [coverage, setCoverage] = useState<CoverageRow[]>([]);
  const [baselines, setBaselines] = useState<BaselineRow[]>([]);
  const [state, setState] = useState<"loading" | "error" | "ready">("loading");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [cl, ev, cov, base] = await Promise.all([
        apiFetch<{ items: ClusterRow[] }>("/kubernetes/clusters"),
        apiFetch<{ items: RuntimeRow[] }>("/kubernetes/runtime-events"),
        apiFetch<{ items: CoverageRow[] }>("/kubernetes/coverage"),
        apiFetch<{ items: BaselineRow[] }>("/kubernetes/baselines"),
      ]);
      setClusters(cl.items ?? []);
      setEvents(ev.items ?? []);
      setCoverage(cov.items ?? []);
      setBaselines(base.items ?? []);
      setState("ready");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to load Kubernetes security");
      setState("error");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const act = async (key: string, fn: () => Promise<string>) => {
    setBusy(key);
    setNotice("");
    try { setNotice(await fn()); } catch (err) { setNotice(err instanceof ApiError ? err.message : "Action failed"); }
    setBusy(null);
  };

  const assess = (id: string) => act(`assess-${id}`, async () => {
    const out = await apiFetch<{ run: { status: string }; rbacRisks: Array<{ kind: string }>; attackPaths: Array<{ id: string }> }>(`/kubernetes/clusters/${id}/assess`, { method: "POST", body: "{}" });
    const cov = await apiFetch<{ items: CoverageRow[] }>("/kubernetes/coverage");
    setCoverage(cov.items ?? []);
    return `Assessment ${out.run.status}; ${out.rbacRisks.length} RBAC risk(s), ${out.attackPaths.length} attack-path candidate(s)`;
  });

  const correlate = (id: string) => act(`corr-${id}`, async () => {
    const out = await apiFetch<{ result: { confidence: string; socAlertRecommended: boolean; detail: string } }>(`/kubernetes/runtime-events/${id}/correlate`, { method: "POST", body: "{}" });
    const ev = await apiFetch<{ items: RuntimeRow[] }>("/kubernetes/runtime-events");
    setEvents(ev.items ?? []);
    return `Correlation: ${out.result.confidence} confidence${out.result.socAlertRecommended ? " — SOC alert linked" : ""}. ${out.result.detail}`;
  });

  const createBaseline = () => act("baseline", async () => {
    const b = await apiFetch<BaselineRow>("/kubernetes/baselines", { method: "POST", body: JSON.stringify({ clusterId: clusters[0]?.id }) });
    const base = await apiFetch<{ items: BaselineRow[] }>("/kubernetes/baselines");
    setBaselines(base.items ?? []);
    return `Kubernetes baseline v${b.version} created`;
  });

  if (state === "loading") return <div className="p-6 text-slate-400">Loading Kubernetes security…</div>;
  if (state === "error") return <div className="p-6 text-red-400">{error}</div>;

  const latest = coverage[0];

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Prompt 34" title="Kubernetes Security" body="Clusters, RBAC, workload posture, benchmarks, Falco runtime signals and baselines (Prompt 34 §130). Analysis only — the platform never acts on a workload." />
      {notice ? <div className="rounded bg-slate-800 px-3 py-2 text-sm text-slate-200">{notice}</div> : null}

      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <StatCard label="Clusters" value={clusters.length} />
        <StatCard label="Runtime events" value={events.length} />
        <StatCard label="Baselines" value={baselines.length} />
        <StatCard label="Latest completion" value={latest?.completion ?? "—"} />
      </div>

      <Card title="Clusters (§71/§72)">
        {clusters.length === 0 ? <EmptyState title="No clusters registered" body="Register a cluster on the Kubernetes page — the kubeconfig stays a secret reference, never content." /> : (
          <table className="w-full text-sm">
            <thead><tr className="text-left text-slate-400"><th className="py-1">Cluster</th><th>Provider</th><th>Environment</th><th>Actions</th></tr></thead>
            <tbody>
              {clusters.map((c) => (
                <tr key={c.id} className="border-t border-slate-800">
                  <td className="py-2"><Link href={`/kubernetes-security/clusters/${c.id}`} className="underline">{c.name}</Link><div className="text-xs text-slate-500">{c.apiServerReference} · {c.version ?? "version unknown"}</div></td>
                  <td>{c.provider}</td>
                  <td><Badge>{c.environment}</Badge></td>
                  <td><button className={btnCls} disabled={busy !== null} onClick={() => void assess(c.id)}>Assess (V2 pipeline)</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <Card title="Runtime security — Falco signals (§91–§96)">
        <p className="mb-2 text-xs text-slate-500">Falco is detection, not enforcement: correlation adds context and may link a SOC alert; it never changes scanner severity and never kills a workload.</p>
        {events.length === 0 ? <EmptyState title="No runtime events" body="Falco events arrive through the governed ingestion path (Prompt 13/28)." /> : (
          <table className="w-full text-sm">
            <thead><tr className="text-left text-slate-400"><th className="py-1">Rule</th><th>Priority</th><th>Pod</th><th>Correlation</th><th>Action</th></tr></thead>
            <tbody>
              {events.slice(0, 20).map((e) => (
                <tr key={e.id} className="border-t border-slate-800">
                  <td className="py-2">{e.rule}<div className="text-xs text-slate-500">{e.eventTime}</div></td>
                  <td><Badge>{e.priority}</Badge></td>
                  <td>{e.namespace ?? ""}/{e.pod ?? ""}</td>
                  <td>{e.correlation ? `${e.correlation.confidence}${e.correlation.socAlertLinked ? " · SOC alert" : ""}` : "—"}</td>
                  <td><button className={btnCls} disabled={busy !== null} onClick={() => void correlate(e.id)}>Correlate</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>

      <Card title="Coverage (§114)">
        {latest ? (
          <div className="text-sm">
            <p>Workloads covered: {latest.workloadsCovered} · RBAC subjects: {latest.rbacSubjects} · Completion: <Badge>{latest.completion}</Badge></p>
            <ul className="mt-2 list-disc pl-5 text-slate-300">{latest.gaps.map((g, i) => <li key={i}>{g.area} — {g.reason}</li>)}</ul>
          </div>
        ) : <EmptyState title="No coverage yet" body="Run a cluster assessment to compute coverage." />}
      </Card>

      <Card title="Kubernetes Security Baseline (§98)">
        <button className={btnCls} disabled={busy !== null || clusters.length === 0} onClick={() => void createBaseline()}>Create baseline version</button>
        <p className="mt-2 text-sm text-slate-400">{baselines.map((b) => `v${b.version} (${b.hash.slice(0, 8)}…)`).join(" · ") || "No baselines yet."}</p>
      </Card>
    </div>
  );
}
