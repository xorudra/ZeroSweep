"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { PageHeader } from "@/components/Shell";
import { Badge, Card } from "@zerosweep/ui";
import { apiFetch } from "@/lib/api-client";

type Row = Record<string, unknown>;
interface Detail {
  case: Row & { id: string; status: string };
  finding: Row;
  sla: Row | null;
  timeline: Row[]; triage: Row[]; assignments: Row[]; plans: Row[];
  workItems: Row[]; fixClaims: Row[]; verificationJobs: Row[];
  exceptions: Row[]; comments: Row[];
}

const TABS = ["Overview", "Finding", "Risk", "Plan", "Ticket", "SLA", "Verification", "Evidence", "Timeline", "Comments", "Exceptions"] as const;

function JsonBlock({ data }: { data: unknown }) {
  return <pre className="overflow-auto whitespace-pre-wrap text-xs text-slate-300">{JSON.stringify(data, null, 2)}</pre>;
}

/**
 * Remediation case detail (Prompt 31 §105). Actions call the governed
 * API only — there is no button here that can mark a finding fixed:
 * verification outcomes come from the verification engine, closure
 * from the closure engine.
 */
export default function Page() {
  const params = useParams<{ id: string }>();
  const [detail, setDetail] = useState<Detail | null>(null);
  const [tab, setTab] = useState<(typeof TABS)[number]>("Overview");
  const [message, setMessage] = useState<string | null>(null);
  const [claimText, setClaimText] = useState("");
  const [triageReason, setTriageReason] = useState("");

  const load = useCallback(() => {
    apiFetch<Detail>(`/remediation/${params.id}`).then(setDetail).catch(() => setDetail(null));
  }, [params.id]);
  useEffect(load, [load]);

  const act = async (label: string, path: string, body: Row) => {
    try {
      await apiFetch(path, { method: "POST", body: JSON.stringify(body) });
      setMessage(`${label}: done`);
      load();
    } catch (e) {
      setMessage(`${label}: ${(e as Error).message}`);
    }
  };

  if (!detail) return <p className="text-sm text-slate-400">Loading…</p>;
  const kase = detail.case;
  const finding = detail.finding;

  return (
    <>
      <PageHeader eyebrow="Remediation case" title={String(finding.title ?? kase.id)} body={`Status ${kase.status} · priority ${String(kase.priority ?? "—")} · due ${kase.dueAt ? new Date(String(kase.dueAt)).toLocaleString() : "no SLA date"}`} />
      {message && <p className="mb-3 text-sm text-amber-300">{message}</p>}
      <div className="mb-4 flex flex-wrap gap-2">
        {TABS.map((t) => (
          <button key={t} onClick={() => setTab(t)} className={`rounded px-2 py-1 text-sm ${tab === t ? "bg-sky-700 text-white" : "bg-slate-800 text-slate-300"}`}>{t}</button>
        ))}
      </div>

      {tab === "Overview" && (
        <Card>
          <div className="grid gap-2 text-sm md:grid-cols-2">
            <p>Owner: {String(kase.teamId ?? kase.ownerId ?? "unassigned")} ({String(kase.ownershipConfidence ?? "—")})</p>
            <p>Verification: {String(kase.verificationState)}</p>
            <p>Regressions: {String(kase.regressionCount ?? 0)}</p>
            <p>SLA policy: {String(kase.slaPolicyId ?? "none assigned")}</p>
          </div>
          <div className="mt-4 space-y-3">
            <div className="flex gap-2">
              <input value={triageReason} onChange={(e) => setTriageReason(e.target.value)} placeholder="Triage reason" className="w-64 rounded bg-slate-800 px-2 py-1 text-sm" />
              <button className="rounded bg-slate-700 px-3 py-1 text-sm" onClick={() => act("Triage", `/remediation/${kase.id}/triage`, { decision: "ACTION_REQUIRED", reason: triageReason })}>Triage: action required</button>
            </div>
            <div className="flex gap-2">
              <input value={claimText} onChange={(e) => setClaimText(e.target.value)} placeholder="What changed? (fix claim)" className="w-64 rounded bg-slate-800 px-2 py-1 text-sm" />
              <button className="rounded bg-slate-700 px-3 py-1 text-sm" onClick={() => act("Fix claim", `/remediation/${kase.id}/fix-claim`, { claimSource: "MANUAL", description: claimText })}>Claim fix</button>
              <button className="rounded bg-slate-700 px-3 py-1 text-sm" onClick={() => act("Request verification", `/remediation/${kase.id}/verify`, { method: "MANUAL_EVIDENCE_REVIEW" })}>Request verification</button>
              <button className="rounded bg-slate-700 px-3 py-1 text-sm" onClick={() => act("Create ticket", `/remediation/${kase.id}/tickets`, { provider: "JIRA" })}>Create Jira work item</button>
              <button className="rounded bg-emerald-800 px-3 py-1 text-sm" onClick={() => act("Close", `/remediation/${kase.id}/close`, { reason: "closure checks passed" })}>Close (checked)</button>
            </div>
            <p className="text-xs text-slate-500">Claiming a fix never verifies it. Closure is refused unless the case is VERIFIED_FIXED or covered by an approved exception.</p>
          </div>
        </Card>
      )}
      {tab === "Finding" && <Card><JsonBlock data={finding} /></Card>}
      {tab === "Risk" && (
        <Card>
          <p className="text-sm">Risk score {String(finding.riskScore ?? "—")} · band {String(finding.riskBand ?? "—")} · CVSS {String(finding.cvssScore ?? "—")} · EPSS {String(finding.epssScore ?? "—")} · KEV {finding.kevListed ? "listed" : "no"}</p>
          <JsonBlock data={finding.riskExplanation ?? {}} />
        </Card>
      )}
      {tab === "Plan" && <Card>{detail.plans.length ? <JsonBlock data={detail.plans} /> : <p className="text-sm text-slate-400">No plan yet. Fixed versions must trace to trusted patch intelligence — they are never invented.</p>}</Card>}
      {tab === "Ticket" && <Card>{detail.workItems.length ? <JsonBlock data={detail.workItems} /> : <p className="text-sm text-slate-400">No work items. Unconfigured providers record FAILED honestly — no fake tickets.</p>}</Card>}
      {tab === "SLA" && <Card>{detail.sla ? <JsonBlock data={detail.sla} /> : <p className="text-sm text-slate-400">No SLA snapshot — no policy resolved for this case.</p>}</Card>}
      {tab === "Verification" && <Card>{detail.verificationJobs.length ? <JsonBlock data={detail.verificationJobs} /> : <p className="text-sm text-slate-400">No verification jobs yet.</p>}</Card>}
      {tab === "Evidence" && (
        <Card>
          <p className="mb-2 text-sm text-slate-400">Fix claims and their evidence references:</p>
          {detail.fixClaims.length ? <JsonBlock data={detail.fixClaims} /> : <p className="text-sm text-slate-400">No fix claims recorded.</p>}
        </Card>
      )}
      {tab === "Timeline" && (
        <Card>
          <ul className="space-y-1 text-sm">
            {detail.timeline.map((h, i) => (
              <li key={i}><Badge>{String(h.toStatus)}</Badge> <span className="text-slate-400">{h.fromStatus ? `from ${String(h.fromStatus)} · ` : ""}{String(h.reason ?? "")} · {h.createdAt ? new Date(String(h.createdAt)).toLocaleString() : ""}</span></li>
            ))}
          </ul>
        </Card>
      )}
      {tab === "Comments" && <Card>{detail.comments.length ? <JsonBlock data={detail.comments} /> : <p className="text-sm text-slate-400">No comments.</p>}</Card>}
      {tab === "Exceptions" && <Card>{detail.exceptions.length ? <JsonBlock data={detail.exceptions} /> : <p className="text-sm text-slate-400">No exceptions. Exceptions always expire — there are no permanent silent exceptions.</p>}</Card>}
    </>
  );
}
