"use client";

import { Suspense, useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { ResourceList, Row } from "@/components/ResourceList";
import { Badge, Card } from "@dsrclone/ui";
import { apiFetch } from "@/lib/api-client";

interface Dashboard {
  buckets: Record<string, number>;
  metrics: {
    totalRequests: number;
    approvalLatencySeconds: number | null;
    successRate: number | null;
    inconclusiveRate: number | null;
    blockedRequests: number;
    policyDenials: number;
    averageDurationSeconds: number | null;
    budgetExhaustions: number;
    killSwitchActivations: number;
  };
}

function Stat({ label, value, hint }: { label: string; value: React.ReactNode; hint?: string }) {
  return (
    <Card>
      <div className="text-xs uppercase tracking-wide text-slate-500">{label}</div>
      <div className="mt-1 text-2xl font-semibold text-slate-100">{value}</div>
      {hint ? <div className="mt-1 text-xs text-slate-500">{hint}</div> : null}
    </Card>
  );
}

function pct(v: number | null): string {
  return v === null || v === undefined ? "—" : `${Math.round(v * 100)}%`;
}

function secs(v: number | null): string {
  return v === null || v === undefined ? "—" : `${v.toFixed(1)}s`;
}

/**
 * Security Validation dashboard (Prompt 16 §54/§82). Validation raises
 * CONFIDENCE in a finding through safe, governed rechecks — it is not
 * exploitation. Buckets and metrics come from real validation rows;
 * empty states stay honest zeros.
 */
function SecurityValidationPage() {
  const [dash, setDash] = useState<Dashboard | null>(null);
  const [status, setStatus] = useState("");

  useEffect(() => {
    apiFetch<Dashboard>("/validations/dashboard").then(setDash).catch(() => setDash(null));
  }, []);

  const b = dash?.buckets ?? {};
  const m = dash?.metrics;

  return (
    <>
      <PageHeader
        eyebrow="Controlled Pentest Validation"
        title="Security Validation"
        body="Controlled, approval-gated validation of findings — safe rechecks only. Prohibited automation (credential attacks, exploitation, lateral movement) can never be planned or executed here."
      />
      <div className="mb-4 flex flex-wrap gap-2 text-sm">
        <Link className="rounded bg-slate-800 px-3 py-1.5 text-slate-200 hover:bg-slate-700" href="/security-validation/approvals">Approvals</Link>
        <Link className="rounded bg-slate-800 px-3 py-1.5 text-slate-200 hover:bg-slate-700" href="/security-validation/settings">Validation Policy</Link>
      </div>

      <div className="mb-6 grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Pending Requests" value={b.pending ?? 0} />
        <Stat label="Approval Required" value={b.approvalRequired ?? 0} />
        <Stat label="Running" value={b.running ?? 0} />
        <Stat label="Verified" value={b.verified ?? 0} hint="safely validated (§60)" />
        <Stat label="Inconclusive" value={b.inconclusive ?? 0} />
        <Stat label="Blocked" value={b.blocked ?? 0} hint="policy / scope / safety" />
        <Stat label="Failed" value={b.failed ?? 0} />
        <Stat label="Expired" value={b.expired ?? 0} />
      </div>

      <div className="mb-6 grid grid-cols-2 gap-3 md:grid-cols-4">
        <Stat label="Success Rate" value={pct(m?.successRate ?? null)} hint="of terminal validations (§82)" />
        <Stat label="Inconclusive Rate" value={pct(m?.inconclusiveRate ?? null)} />
        <Stat label="Avg Approval Latency" value={secs(m?.approvalLatencySeconds ?? null)} />
        <Stat label="Avg Duration" value={secs(m?.averageDurationSeconds ?? null)} />
        <Stat label="Policy Denials" value={m?.policyDenials ?? 0} />
        <Stat label="Budget Exhaustions" value={m?.budgetExhaustions ?? 0} />
        <Stat label="Kill-Switch Activations" value={m?.killSwitchActivations ?? 0} />
        <Stat label="Total Requests" value={m?.totalRequests ?? 0} />
      </div>

      <div className="mb-3 flex items-center gap-2">
        <label className="text-sm text-slate-400" htmlFor="status-filter">Status</label>
        <select
          id="status-filter"
          className="rounded bg-slate-900 px-2 py-1 text-sm text-slate-200"
          value={status}
          onChange={(e) => setStatus(e.target.value)}
        >
          {["", "REQUESTED", "APPROVAL_REQUIRED", "APPROVED", "RUNNING", "SUCCEEDED", "FAILED", "INCONCLUSIVE", "BLOCKED", "CANCELLED", "EXPIRED"].map((s) => (
            <option key={s} value={s}>{s || "All"}</option>
          ))}
        </select>
      </div>

      <ResourceList
        path={status ? `/validations?status=${status}` : "/validations"}
        emptyTitle="No validation requests"
        emptyBody="Request a validation from a finding's detail page. Only governed safe rechecks exist — nothing here can exploit a target."
        columns={["Validator", "Status", "Risk", "Outcome", "Finding", "Requested"]}
        renderRow={(r: Record<string, unknown>, i: number) => (
          <Row key={i} cells={[
            <Link key="v" className="text-cyan-300 hover:underline" href={`/security-validation/${String(r.id)}`}>{String(r.validatorSlug ?? "")}</Link>,
            <Badge key="s">{String(r.status ?? "")}</Badge>,
            <Badge key="r">{String(r.riskClass ?? "")}</Badge>,
            r.outcome ? String(r.outcome) : "—",
            <Link key="f" className="text-cyan-300 hover:underline" href={`/findings/${String(r.findingId ?? "")}`}>{String(r.validationType ?? "")}</Link>,
            r.createdAt ? new Date(String(r.createdAt)).toLocaleString() : "—",
          ]} />
        )}
      />
    </>
  );
}

export default function Page() {
  return (
    <Suspense fallback={<p className="text-sm text-slate-400">Loading…</p>}>
      <SecurityValidationPage />
    </Suspense>
  );
}
