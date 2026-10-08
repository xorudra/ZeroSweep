"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Cluster Detail (Prompt 34 §131): Overview · Namespaces · Workloads
 * · RBAC · Benchmarks · Images · Exposure · Runtime · Baseline ·
 * Coverage · History. Attack paths are labelled Observed Evidence /
 * Inferred Relationship / Potential Path (§132) and are never
 * executed (§90).
 */
interface ClusterDetail { id: string; name: string; provider: string; version?: string | null; environment: string; apiServerReference: string; workloads?: Array<{ id: string; namespace: string; kind: string; name: string; exposure: string; securityContext?: { privileged?: boolean } }> }
interface RbacData { risks: Array<{ kind: string; severity: string; subject: string; message: string }>; edges: Array<{ from: string; to: string; relationship: string }> }
interface AssessData { attackPaths: Array<{ id: string; steps: Array<{ label: string; evidence: string }>; confidence: string }>; admission: Array<{ kind: string; message: string }>; run: { status: string } }

const btnCls = "rounded bg-slate-800 px-2 py-1 text-xs text-slate-200 hover:bg-slate-700 disabled:opacity-50";

export default function Page() {
  const params = useParams<{ id: string }>();
  const id = params.id;
  const [cluster, setCluster] = useState<ClusterDetail | null>(null);
  const [rbac, setRbac] = useState<RbacData | null>(null);
  const [assess, setAssess] = useState<AssessData | null>(null);
  const [deviations, setDeviations] = useState<Array<{ ruleId: string; message: string }>>([]);
  const [state, setState] = useState<"loading" | "error" | "ready">("loading");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const [cl, rb] = await Promise.all([
        apiFetch<ClusterDetail>(`/kubernetes/clusters/${id}`),
        apiFetch<RbacData>(`/kubernetes/rbac?clusterId=${encodeURIComponent(id)}`).catch(() => null),
      ]);
      setCluster(cl);
      setRbac(rb);
      setState("ready");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Failed to load cluster");
      setState("error");
    }
  }, [id]);

  useEffect(() => { void load(); }, [load]);

  const runAssess = async () => {
    setBusy(true);
    setNotice("");
    try {
      const out = await apiFetch<AssessData>(`/kubernetes/clusters/${id}/assess`, { method: "POST", body: "{}" });
      setAssess(out);
      setNotice(`Assessment ${out.run.status}`);
    } catch (err) {
      setNotice(err instanceof ApiError ? err.message : "Assessment failed");
    }
    setBusy(false);
  };

  const checkDrift = async () => {
    setBusy(true);
    try {
      const out = await apiFetch<{ deviations: Array<{ ruleId: string; message: string }> }>(`/kubernetes/baseline-drift?clusterId=${encodeURIComponent(id)}`);
      setDeviations(out.deviations ?? []);
      setNotice(`${(out.deviations ?? []).length} baseline deviation(s)`);
    } catch (err) {
      setNotice(err instanceof ApiError ? err.message : "Drift check failed");
    }
    setBusy(false);
  };

  if (state === "loading") return <div className="p-6 text-slate-400">Loading cluster…</div>;
  if (state === "error" || !cluster) return <div className="p-6 text-red-400">{error || "Cluster not found"}</div>;

  const workloads = cluster.workloads ?? [];

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Prompt 34" title={cluster.name} body={`Cluster detail (Prompt 34 §131) — ${cluster.provider} · ${cluster.environment} · API server reference ${cluster.apiServerReference} (kubeconfig content is never stored, §72).`} />
      <p className="text-sm text-slate-400"><Link href="/kubernetes-security" className="underline">← Kubernetes security</Link></p>
      {notice ? <div className="rounded bg-slate-800 px-3 py-2 text-sm text-slate-200">{notice}</div> : null}

      <Card title="Overview & workloads (§73/§75)">
        <p className="text-sm text-slate-300">{workloads.length} workload(s) recorded. Version: {cluster.version ?? "unknown"}.</p>
        {workloads.length ? (
          <table className="mt-2 w-full text-sm">
            <thead><tr className="text-left text-slate-400"><th className="py-1">Workload</th><th>Exposure</th><th>Privileged</th></tr></thead>
            <tbody>
              {workloads.slice(0, 30).map((w) => (
                <tr key={w.id} className="border-t border-slate-800">
                  <td className="py-1">{w.namespace}/{w.kind}/{w.name}</td>
                  <td><Badge>{w.exposure}</Badge></td>
                  <td>{w.securityContext?.privileged ? <Badge>privileged</Badge> : "no"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
        <div className="mt-3 flex gap-2">
          <button className={btnCls} disabled={busy} onClick={() => void runAssess()}>Run V2 assessment</button>
          <button className={btnCls} disabled={busy} onClick={() => void checkDrift()}>Baseline drift</button>
        </div>
      </Card>

      <Card title="RBAC (§76/§77) — analyzed, never used">
        {rbac ? (
          rbac.risks.length ? (
            <ul className="list-disc pl-5 text-sm text-slate-300">
              {rbac.risks.map((r, i) => <li key={i}><Badge>{r.severity}</Badge> {r.kind} — {r.subject}: {r.message}</li>)}
            </ul>
          ) : <p className="text-sm text-slate-400">No RBAC risks in the recorded inventory. Graph edges: {rbac.edges.length}.</p>
        ) : <EmptyState title="RBAC not visible" body="RBAC viewing requires the VIEW_KUBERNETES_RBAC permission (leads). Import inventory via POST /kubernetes/clusters/:id/rbac." />}
      </Card>

      <Card title="Admission posture (§85)">
        {assess ? (
          <ul className="list-disc pl-5 text-sm text-slate-300">{assess.admission.map((a, i) => <li key={i}>{a.kind}: {a.message}</li>)}</ul>
        ) : <p className="text-sm text-slate-400">Run the assessment with PSA levels / policy engines to evaluate admission posture (PSS, Kyverno, Gatekeeper, image policy).</p>}
      </Card>

      <Card title="Attack-path candidates (§89) — Observed Evidence · Inferred Relationship · Potential Path">
        {assess ? (
          assess.attackPaths.length ? (
            <div className="space-y-2 text-sm">
              {assess.attackPaths.map((p) => (
                <div key={p.id} className="rounded bg-slate-900 p-2">
                  <p>Confidence <Badge>{p.confidence}</Badge> — analytical only, never executed (§90)</p>
                  <ol className="mt-1 list-decimal pl-5 text-slate-300">{p.steps.map((s, i) => <li key={i}>{s.label} <span className="text-xs text-slate-500">[{s.evidence}]</span></li>)}</ol>
                </div>
              ))}
            </div>
          ) : <p className="text-sm text-slate-400">No candidates from the recorded inventory.</p>
        ) : <p className="text-sm text-slate-400">Run the assessment to derive candidates.</p>}
      </Card>

      <Card title="Baseline drift (§100)">
        {deviations.length ? <ul className="list-disc pl-5 text-sm text-slate-300">{deviations.map((d) => <li key={d.ruleId}>{d.ruleId}: {d.message}</li>)}</ul> : <p className="text-sm text-slate-400">No deviations computed yet — create a baseline on the Kubernetes Security page, then check drift.</p>}
      </Card>

      <Card title="Benchmarks & runtime (§78/§91)">
        <p className="text-sm text-slate-300">CIS Kubernetes Benchmark results (kube-bench, Kubescape) are posture EVIDENCE — never a certification claim (§79). Falco runtime events for this cluster are listed on the Kubernetes Security dashboard; correlation links vulnerable workloads to the SOC without changing severity (§95).</p>
      </Card>
    </div>
  );
}
