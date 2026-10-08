"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { Badge, Card, EmptyState } from "@dsrclone/ui";
import { apiFetch } from "@/lib/api-client";

interface Step { id: string; objective: string; capability: string; riskClass: string; approvalRequired: boolean; scanProfile?: string; targetReferences: string[] }
interface WorkflowDetail {
  workflow: {
    id: string; taskType: string; objective: string; status: string; mode: string;
    authorizationSnapshotHash: string; createdAt: string;
    plan: { steps: Step[] };
    validation: { verdict: string; findings: { stepId: string; severity: string; reason: string }[]; snapshotHashVerified: boolean };
    result?: { steps?: { stepId: string; capability: string; verdict: string; summary: string }[] } | null;
  };
  approvals: { id: string; decision: string; riskClass: string; requestedBy: string; approvedBy?: string | null; expiresAt: string }[];
}

/**
 * Plan detail (Prompt 36 §137): steps, validator findings, the bound
 * authorization snapshot hash, approvals and execution results.
 * Steps hand work to governed platform workflows — the AI itself
 * executes nothing (§26/§33).
 */
export default function AiPlanDetailPage() {
  const params = useParams<{ id: string }>();
  const [data, setData] = useState<WorkflowDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const load = () => { apiFetch<WorkflowDetail>(`/ai/plans/${params.id}`).then(setData).catch((e: Error) => setError(e.message)); };
  useEffect(load, [params.id]);

  const act = async (action: "approve" | "reject" | "execute") => {
    setBusy(true); setError(null); setNotice(null);
    try {
      const out = await apiFetch<{ workflow: { status: string } }>(`/ai/workflows/${params.id}/${action}`, { method: "POST", body: "{}" });
      setNotice(`Workflow is now ${out.workflow.status}.`);
      load();
    } catch (e) { setError((e as Error).message); }
    finally { setBusy(false); }
  };

  const w = data?.workflow;
  return (
    <>
      <PageHeader eyebrow="AI Security Copilot V2" title={w ? w.objective : "Plan"}
        body="Validated against the authorization snapshot shown below. Approval is a human act — the AI can never approve its own plan (§49), and separation of duties applies to high-risk approvals (§143)." />
      <p className="mb-4 text-sm"><Link className="text-cyan-300 hover:underline" href="/ai-security/plans">← All plans</Link></p>
      {error && <p className="mb-4 text-sm text-rose-300">{error}</p>}
      {notice && <p className="mb-4 text-sm text-emerald-300">{notice}</p>}
      {!w ? <EmptyState title="Loading…" body="Fetching governed data for this workspace." /> : (
        <>
          <div className="mb-4 flex flex-wrap items-center gap-2">
            <Badge tone={w.status === "COMPLETED" ? "ok" : w.status === "REJECTED" || w.status === "FAILED" ? "danger" : "warn"}>{w.status}</Badge>
            <Badge>{w.taskType}</Badge>
            <Badge>validator: {w.validation.verdict}</Badge>
            <Badge>snapshot hash verified: {String(w.validation.snapshotHashVerified)}</Badge>
            {w.status === "AWAITING_APPROVAL" && (
              <>
                <button disabled={busy} onClick={() => void act("approve")} className="rounded-lg bg-emerald-500/10 px-3 py-1.5 text-sm text-emerald-300 hover:bg-emerald-500/20 disabled:opacity-50">Approve</button>
                <button disabled={busy} onClick={() => void act("reject")} className="rounded-lg bg-rose-500/10 px-3 py-1.5 text-sm text-rose-300 hover:bg-rose-500/20 disabled:opacity-50">Reject</button>
              </>
            )}
            {w.status === "APPROVED" && (
              <button disabled={busy} onClick={() => void act("execute")} className="rounded-lg bg-cyan-500/10 px-3 py-1.5 text-sm text-cyan-300 hover:bg-cyan-500/20 disabled:opacity-50">Execute workflow</button>
            )}
          </div>

          <Card title="Steps (§42)" eyebrow={`Authorization snapshot ${w.authorizationSnapshotHash}`}>
            <ul className="space-y-2 text-sm text-slate-300">
              {w.plan.steps.map((s) => (
                <li key={s.id} className="rounded-lg border border-slate-800 p-3">
                  <p className="text-slate-100">{s.id} · {s.objective}</p>
                  <p className="text-xs text-slate-500">capability {s.capability} · risk {s.riskClass} · approval {s.approvalRequired ? "required" : "not required"}{s.scanProfile ? ` · profile ${s.scanProfile}` : ""}{s.targetReferences.length ? ` · targets ${s.targetReferences.join(", ")}` : ""}</p>
                </li>
              ))}
            </ul>
          </Card>

          <div className="mt-4 grid gap-4 md:grid-cols-2">
            <Card title="Validator findings (§44)" eyebrow="Deterministic — no AI judgment">
              {w.validation.findings.length === 0 ? <EmptyState title="No findings" body="The plan validated cleanly against the snapshot." /> : (
                <ul className="space-y-1 text-sm text-slate-300">
                  {w.validation.findings.map((f, i) => <li key={i}><Badge tone={f.severity === "REJECT" ? "danger" : "warn"}>{f.severity}</Badge> {f.stepId}: {f.reason}</li>)}
                </ul>
              )}
            </Card>
            <Card title="Approvals (§48–§50)" eyebrow="Approvals expire and cannot be reused">
              {data.approvals.length === 0 ? <EmptyState title="No approvals" body="This workflow has no approval records." /> : (
                <ul className="space-y-1 text-sm text-slate-300">
                  {data.approvals.map((a) => (
                    <li key={a.id} className="flex items-center justify-between">
                      <span>risk {a.riskClass} · requested by {a.requestedBy.slice(0, 8)}…{a.approvedBy ? ` · decided by ${a.approvedBy.slice(0, 8)}…` : ""} · expires {new Date(a.expiresAt).toLocaleString()}</span>
                      <Badge tone={a.decision === "APPROVED" ? "ok" : a.decision === "REJECTED" ? "danger" : "warn"}>{a.decision}</Badge>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
          </div>

          {w.result?.steps && (
            <div className="mt-4">
              <Card title="Execution results" eyebrow="Hand-offs to governed workflows — executed: false for the AI itself">
                <ul className="space-y-1 text-sm text-slate-300">
                  {w.result.steps.map((s, i) => <li key={i}>{s.stepId} · {s.capability}: <b>{s.verdict}</b> — {s.summary}</li>)}
                </ul>
              </Card>
            </div>
          )}
        </>
      )}
    </>
  );
}
