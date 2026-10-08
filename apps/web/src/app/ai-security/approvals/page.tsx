"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { Badge, Card, EmptyState } from "@dsrclone/ui";
import { apiFetch } from "@/lib/api-client";

interface Approval {
  id: string; workflowId: string; decision: string; riskClass: string; reason: string;
  requestedBy: string; approvedBy?: string | null; expiresAt: string; createdAt: string;
}

/**
 * AI approval queue (Prompt 36 §138). Approving is a human decision
 * recorded with identity and expiry; separation of duties blocks
 * self-approval of HIGH/CRITICAL risk (§143), and the AI can never
 * appear as an approver (§49).
 */
export default function AiApprovalsPage() {
  const [rows, setRows] = useState<Approval[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = () => { apiFetch<Approval[]>("/ai/approvals").then(setRows).catch((e: Error) => setError(e.message)); };
  useEffect(load, []);

  const decide = async (a: Approval, decision: "approve" | "reject") => {
    setBusyId(a.id); setError(null); setNotice(null);
    try {
      await apiFetch(`/ai/workflows/${a.workflowId}/${decision}`, { method: "POST", body: "{}" });
      setNotice(`Approval ${decision === "approve" ? "recorded" : "rejected"} for workflow ${a.workflowId.slice(0, 8)}….`);
      load();
    } catch (e) { setError((e as Error).message); }
    finally { setBusyId(null); }
  };

  const pending = rows?.filter((r) => r.decision === "PENDING") ?? [];
  const decided = rows?.filter((r) => r.decision !== "PENDING") ?? [];

  return (
    <>
      <PageHeader eyebrow="AI Security Copilot V2" title="Approval queue"
        body="Nothing the AI proposes with approval-required risk runs without a human decision recorded here. Expired approvals cannot be reused (§50)." />
      {error && <p className="mb-4 text-sm text-rose-300">{error}</p>}
      {notice && <p className="mb-4 text-sm text-emerald-300">{notice}</p>}

      <Card title={`Pending (${pending.length})`} eyebrow="Decide with full plan context — open the plan for steps and validator findings">
        {rows === null ? <EmptyState title="Loading…" body="Fetching governed data for this workspace." /> : pending.length === 0 ? (
          <EmptyState title="Nothing pending" body="When a validated plan needs approval, it appears here with its risk class and expiry." />
        ) : (
          <ul className="divide-y divide-slate-800">
            {pending.map((a) => (
              <li key={a.id} className="flex flex-wrap items-center justify-between gap-2 py-2 text-sm">
                <div>
                  <Link href={`/ai-security/plans/${a.workflowId}`} className="text-cyan-300 hover:underline">{a.reason}</Link>
                  <p className="text-xs text-slate-500">risk {a.riskClass} · requested by {a.requestedBy.slice(0, 8)}… · expires {new Date(a.expiresAt).toLocaleString()}</p>
                </div>
                <div className="flex gap-2">
                  <button disabled={busyId === a.id} onClick={() => void decide(a, "approve")} className="rounded-lg bg-emerald-500/10 px-3 py-1.5 text-emerald-300 hover:bg-emerald-500/20 disabled:opacity-50">Approve</button>
                  <button disabled={busyId === a.id} onClick={() => void decide(a, "reject")} className="rounded-lg bg-rose-500/10 px-3 py-1.5 text-rose-300 hover:bg-rose-500/20 disabled:opacity-50">Reject</button>
                </div>
              </li>
            ))}
          </ul>
        )}
      </Card>

      <div className="mt-4">
        <Card title="Decision history" eyebrow="Immutable record">
          {decided.length === 0 ? <EmptyState title="No decisions yet" body="Approved and rejected requests remain visible for audit." /> : (
            <ul className="divide-y divide-slate-800">
              {decided.map((a) => (
                <li key={a.id} className="flex items-center justify-between py-2 text-sm">
                  <span>{a.reason} <span className="text-slate-500">· risk {a.riskClass} · {new Date(a.createdAt).toLocaleString()}</span></span>
                  <Badge tone={a.decision === "APPROVED" ? "ok" : "danger"}>{a.decision}</Badge>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </>
  );
}
