"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { Badge, Card, EmptyState } from "@zerosweep/ui";
import { apiFetch, ApiError } from "@/lib/api-client";

type ValidationRequest = Record<string, unknown> & {
  id: string;
  approvals?: Record<string, unknown>[];
  sessions?: Record<string, unknown>[];
};

/**
 * Validation approvals (Prompt 16 §56). Approvers see the requester,
 * target, finding, validation method, risk class, scope, budget and
 * reason BEFORE deciding. An approval binds to the exact plan hash —
 * any plan change voids it (§10) — and separation of duties prevents
 * self-approval of higher-risk validations (§11).
 */
export default function Page() {
  const [items, setItems] = useState<ValidationRequest[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [reasons, setReasons] = useState<Record<string, string>>({});

  const load = useCallback(async () => {
    try {
      setItems(await apiFetch<ValidationRequest[]>("/validations?status=APPROVAL_REQUIRED"));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not load approvals.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const decide = async (id: string, decision: "approve" | "reject") => {
    setBusy(id);
    setNotice(null);
    try {
      await apiFetch(`/validations/${id}/${decision}`, { method: "POST", body: JSON.stringify({ reason: reasons[id] ?? "" }) });
      setNotice(decision === "approve" ? "Approved — bound to the plan hash and dispatched to a validation worker." : "Rejected — the request is blocked and the decision is audited.");
      await load();
    } catch (e) {
      setNotice(e instanceof ApiError ? e.message : "Decision failed.");
    } finally {
      setBusy(null);
    }
  };

  if (error) return <EmptyState title="Approvals unavailable" body={error} />;
  if (!items) return <p className="text-sm text-slate-400">Loading…</p>;

  return (
    <>
      <PageHeader
        eyebrow="Security Validation"
        title="Validation Approvals"
        body="Approvals are specific to target + finding + technique and expire. Approving never widens scope or budget."
      />
      {notice ? <p className="mb-4 rounded bg-slate-900 px-3 py-2 text-sm text-slate-200">{notice}</p> : null}
      {items.length === 0 ? (
        <EmptyState title="Nothing awaiting approval" body="Validations that require approval (REVIEW_REQUIRED, LOW_IMPACT under SAFE_ONLY, high-criticality assets) will appear here." />
      ) : (
        <div className="space-y-4">
          {items.map((r) => {
            const budget = (r.budget ?? {}) as Record<string, unknown>;
            const authz = (r.authorizationSnapshot ?? {}) as Record<string, unknown>;
            return (
              <Card key={r.id}>
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-medium text-slate-100">{String(r.validatorSlug ?? "")}</span>
                  <Badge>{`Risk: ${String(r.riskClass ?? "")}`}</Badge>
                  <Badge>{String(r.validationType ?? "")}</Badge>
                  <span className="text-xs text-slate-500">requested by {String(r.requestedBy ?? "")}</span>
                </div>
                <dl className="mt-3 grid grid-cols-2 gap-3 md:grid-cols-4">
                  <div><dt className="text-xs uppercase tracking-wide text-slate-500">Finding</dt><dd className="mt-1 text-sm text-slate-200"><Link className="text-cyan-300 hover:underline" href={`/findings/${String(r.findingId)}`}>{String(r.findingId)}</Link></dd></div>
                  <div><dt className="text-xs uppercase tracking-wide text-slate-500">Target</dt><dd className="mt-1 text-sm text-slate-200">{String(r.targetId ?? "")}</dd></div>
                  <div><dt className="text-xs uppercase tracking-wide text-slate-500">Authorization</dt><dd className="mt-1 text-sm text-slate-200">{authz.targetVerified ? "verified" : "UNVERIFIED"} · {authz.assessmentApproved ? "assessment approved" : "NOT APPROVED"}</dd></div>
                  <div><dt className="text-xs uppercase tracking-wide text-slate-500">Budget</dt><dd className="mt-1 text-sm text-slate-200">{String(budget.maxRequests ?? "—")} req · {String(budget.maxDurationSeconds ?? "—")}s · {String(budget.maxBytes ?? "—")} bytes</dd></div>
                </dl>
                {r.reason ? <p className="mt-3 text-sm text-slate-300">Reason: {String(r.reason)}</p> : null}
                <div className="mt-3 flex flex-wrap items-center gap-2">
                  <input
                    className="min-w-64 flex-1 rounded bg-slate-900 px-3 py-2 text-sm text-slate-200"
                    placeholder="Decision reason (recorded in the audit log)"
                    value={reasons[r.id] ?? ""}
                    onChange={(e) => setReasons((prev) => ({ ...prev, [r.id]: e.target.value }))}
                  />
                  <button disabled={busy === r.id} onClick={() => void decide(r.id, "approve")} className="rounded bg-emerald-700 px-3 py-2 text-sm text-white hover:bg-emerald-600 disabled:opacity-50">Approve</button>
                  <button disabled={busy === r.id} onClick={() => void decide(r.id, "reject")} className="rounded bg-rose-800 px-3 py-2 text-sm text-white hover:bg-rose-700 disabled:opacity-50">Reject</button>
                  <Link className="text-sm text-cyan-300 hover:underline" href={`/security-validation/${r.id}`}>Full request</Link>
                </div>
              </Card>
            );
          })}
        </div>
      )}
    </>
  );
}
