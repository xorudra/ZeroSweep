"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { PageHeader } from "@/components/Shell";
import { Badge, Card, EmptyState } from "@zerosweep/ui";
import { apiFetch, ApiError } from "@/lib/api-client";

type Req = Record<string, unknown> & {
  id: string;
  approvals?: Record<string, unknown>[];
  sessions?: (Record<string, unknown> & { evidence?: Record<string, unknown>[] })[];
  evidence?: Record<string, unknown>[];
};

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wide text-slate-500">{label}</dt>
      <dd className="mt-1 text-sm text-slate-200">{value}</dd>
    </div>
  );
}

/**
 * Validation request + session detail (Prompt 16 §55/§57): plan,
 * authorization snapshot, approval record, risk classification, scope,
 * budget, sessions with budget consumption and termination reason, and
 * the sanitized, checksummed evidence (§33–§35).
 */
export default function Page() {
  const params = useParams<{ id: string }>();
  const id = params.id;
  const [request, setRequest] = useState<Req | null>(null);
  const [proof, setProof] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setRequest(await apiFetch<Req>(`/validations/${id}`));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not load the validation request.");
    }
  }, [id]);

  useEffect(() => { void load(); }, [load]);

  const loadProof = async () => {
    try {
      const p = await apiFetch<{ proof: string }>(`/validations/${id}/proof`);
      setProof(p.proof);
    } catch (e) {
      setNotice(e instanceof ApiError ? e.message : "Proof unavailable.");
    }
  };

  const cancel = async () => {
    setBusy(true);
    try {
      await apiFetch(`/validations/${id}/cancel`, { method: "POST", body: JSON.stringify({}) });
      setNotice("Cancellation recorded. A running session is terminated through the session kill switch (§43).");
      await load();
    } catch (e) {
      setNotice(e instanceof ApiError ? e.message : "Cancel failed.");
    } finally {
      setBusy(false);
    }
  };

  if (error) return <EmptyState title="Request not found" body={error} />;
  if (!request) return <p className="text-sm text-slate-400">Loading…</p>;

  const authz = (request.authorizationSnapshot ?? {}) as Record<string, unknown>;
  const budget = (request.budget ?? {}) as Record<string, unknown>;
  const plan = (request.plan ?? {}) as Record<string, unknown>;
  const stages = Array.isArray(plan.stages) ? (plan.stages as string[]) : [];
  const cancellable = ["REQUESTED", "POLICY_REVIEW", "APPROVAL_REQUIRED", "APPROVED", "RUNNING"].includes(String(request.status));

  return (
    <>
      <PageHeader eyebrow="Validation Request" title={`Validation ${String(request.validatorSlug ?? "")}`} body={String(request.id)} />
      {notice ? <p className="mb-4 rounded bg-slate-900 px-3 py-2 text-sm text-slate-200">{notice}</p> : null}
      <div className="mb-4 flex flex-wrap gap-2">
        <Badge>{String(request.status ?? "")}</Badge>
        <Badge>{`Risk: ${String(request.riskClass ?? "")}`}</Badge>
        {request.outcome ? <Badge>{`Outcome: ${String(request.outcome)}`}</Badge> : null}
        <Badge>{`Policy: ${String(request.policyDecision ?? "—")}`}</Badge>
        {cancellable ? <button disabled={busy} onClick={() => void cancel()} className="rounded bg-rose-800 px-3 py-1 text-sm text-white hover:bg-rose-700 disabled:opacity-50">Cancel validation</button> : null}
        <button onClick={() => void loadProof()} className="rounded bg-slate-800 px-3 py-1 text-sm text-slate-200 hover:bg-slate-700">Proof of validation (§61)</button>
      </div>
      {proof ? <Card><p className="whitespace-pre-wrap text-sm text-slate-200">{proof}</p></Card> : null}

      <Card>
        <dl className="grid grid-cols-2 gap-4 md:grid-cols-4">
          <Field label="Finding" value={<Link className="text-cyan-300 hover:underline" href={`/findings/${String(request.findingId)}`}>{String(request.findingId)}</Link>} />
          <Field label="Target" value={String(request.targetId ?? "")} />
          <Field label="Validator / Tool" value={`${String(request.validatorSlug ?? "")} · ${String(request.toolSlug ?? "")}`} />
          <Field label="Requested By" value={String(request.requestedBy ?? "")} />
          <Field label="Authorization" value={`${authz.targetVerified ? "target verified" : "UNVERIFIED"} · ${authz.assessmentApproved ? "assessment approved" : "NOT APPROVED"}`} />
          <Field label="Budget" value={`${String(budget.maxRequests ?? "—")} req · ${String(budget.maxDurationSeconds ?? "—")}s · ${String(budget.maxBytes ?? "—")} B · ≤${String(budget.maxRedirects ?? "—")} redirects`} />
          <Field label="Environment" value={String(request.environment ?? "PRODUCTION")} />
          <Field label="Plan Hash" value={<span className="font-mono text-xs">{String(request.planHash ?? "")}</span>} />
        </dl>
        {request.reason ? <p className="mt-3 text-sm text-slate-300">Reason: {String(request.reason)}</p> : null}
        {request.policyReason ? <p className="mt-2 text-sm text-amber-300">Policy: {String(request.policyReason)}</p> : null}
        {stages.length ? <p className="mt-3 text-xs text-slate-500">Workflow: {stages.join(" → ")}</p> : null}
      </Card>

      <h2 className="mb-2 mt-6 text-lg font-semibold text-slate-100">Approvals</h2>
      {(request.approvals ?? []).length === 0 ? <p className="text-sm text-slate-400">No approval records.</p> : (
        <div className="space-y-2">
          {(request.approvals ?? []).map((a) => (
            <Card key={String(a.id)}>
              <div className="flex flex-wrap gap-2 text-sm text-slate-200">
                <Badge>{String(a.decision ?? "")}</Badge>
                <span>by {String(a.approverId ?? "")}</span>
                <span className="text-slate-500">expires {a.expiresAt ? new Date(String(a.expiresAt)).toLocaleString() : "—"}</span>
              </div>
              {a.reason ? <p className="mt-1 text-sm text-slate-400">{String(a.reason)}</p> : null}
            </Card>
          ))}
        </div>
      )}

      <h2 className="mb-2 mt-6 text-lg font-semibold text-slate-100">Sessions</h2>
      {(request.sessions ?? []).length === 0 ? <p className="text-sm text-slate-400">No execution session yet. Sessions run in isolated validation workers, never in the API (§45).</p> : (
        <div className="space-y-2">
          {(request.sessions ?? []).map((s) => {
            const consumed = (s.budgetConsumed ?? {}) as Record<string, unknown>;
            return (
              <Card key={String(s.id)}>
                <div className="flex flex-wrap gap-2 text-sm text-slate-200">
                  <Badge>{String(s.status ?? "")}</Badge>
                  <span>{String(s.validatorSlug ?? "")} via {String(s.toolSlug ?? "")}</span>
                  <span className="text-slate-500">worker {String(s.workerId ?? "—")}</span>
                  {s.terminationReason ? <span className="text-amber-300">terminated: {String(s.terminationReason)}</span> : null}
                </div>
                <p className="mt-1 text-xs text-slate-500">
                  {s.startedAt ? `started ${new Date(String(s.startedAt)).toLocaleString()}` : "not started"}
                  {s.endedAt ? ` · ended ${new Date(String(s.endedAt)).toLocaleString()}` : ""}
                  {` · budget used: ${String(consumed.requests ?? 0)} requests, ${String(consumed.bytes ?? 0)} bytes`}
                </p>
              </Card>
            );
          })}
        </div>
      )}

      <h2 className="mb-2 mt-6 text-lg font-semibold text-slate-100">Evidence</h2>
      {(request.evidence ?? []).length === 0 ? <p className="text-sm text-slate-400">No evidence captured. Evidence is sanitized before storage and checksummed for integrity (§34/§35).</p> : (
        <div className="space-y-2">
          {(request.evidence ?? []).map((e) => (
            <Card key={String(e.id)}>
              <div className="flex flex-wrap gap-2 text-sm text-slate-200">
                <Badge>{String(e.type ?? "")}</Badge>
                <span>{String(e.summary ?? "")}</span>
              </div>
              <p className="mt-1 font-mono text-xs text-slate-500">sha256 {String(e.checksum ?? "")} · source {String(e.sourceTool ?? "")}</p>
            </Card>
          ))}
        </div>
      )}
    </>
  );
}
