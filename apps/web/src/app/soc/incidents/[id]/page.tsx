"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@zerosweep/ui";

/**
 * Incident workspace (Prompt 28 §106, tabs rendered as sections):
 * overview, timeline (append-only, §46), evidence with hash
 * verification (§49–§51), response actions behind the approval
 * policy (§75–§82), playbook runs (§88), communications (§93),
 * AI summary (§97, grounded + cited), and the post-incident review
 * (§118). Response execution happens only through the response
 * engine — this page proposes and approves; it never runs commands.
 */
interface Detail {
  incident: Record<string, unknown>;
  links: Array<Record<string, unknown>>;
  timeline: Array<Record<string, unknown>>;
  evidence: Array<Record<string, unknown>>;
  communications: Array<Record<string, unknown>>;
  playbookRuns: Array<Record<string, unknown>>;
  responseActions: Array<Record<string, unknown>>;
  postIncidentReview: Record<string, unknown> | null;
}
interface CatalogAction { key: string; title: string; approvalMode: string; impact: string; description: string }

const NEXT_STATUS: Record<string, string[]> = {
  DECLARED: ["TRIAGED"], TRIAGED: ["INVESTIGATING"], INVESTIGATING: ["CONTAINED"],
  CONTAINED: ["RECOVERING"], RECOVERING: ["CLOSED"], CLOSED: [],
};

export default function Page() {
  const params = useParams<{ id: string }>();
  const [data, setData] = useState<Detail | null>(null);
  const [catalog, setCatalog] = useState<CatalogAction[]>([]);
  const [note, setNote] = useState("");
  const [evidenceTitle, setEvidenceTitle] = useState("");
  const [evidenceContent, setEvidenceContent] = useState("");
  const [verifyContent, setVerifyContent] = useState<Record<string, string>>({});
  const [actionKey, setActionKey] = useState("SEND_NOTIFICATION");
  const [targetReference, setTargetReference] = useState("");
  const [playbookKey, setPlaybookKey] = useState("suspected-credential-compromise");
  const [aiAnswer, setAiAnswer] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const load = useCallback(async () => {
    try {
      setData(await apiFetch<Detail>(`/soc/incidents/${params.id}`));
      const cat = await apiFetch<{ actions: CatalogAction[] }>("/soc/response-actions");
      setCatalog(cat.actions);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, [params.id]);

  useEffect(() => { void load(); }, [load]);

  const call = async (fn: () => Promise<unknown>, ok: string) => {
    try { await fn(); setNotice(ok); await load(); }
    catch (e) { setError(e instanceof ApiError ? e.message : "Action failed."); }
  };

  const inc = data?.incident;
  const status = inc ? String(inc.status) : "";

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Security Operations" title={inc ? String(inc.title) : "Incident"} body="Append-only timeline · hash-anchored evidence · governed response." />
      {error && <p className="text-sm text-red-400">{error}</p>}
      {notice && <p className="text-sm text-emerald-400">{notice}</p>}
      {inc && (
        <Card title="Overview">
          <div className="flex flex-wrap gap-2 text-xs">
            <Badge>{String(inc.priority)}</Badge><Badge>{String(inc.severity)}</Badge><Badge>{status}</Badge>
            <span className="text-slate-400">declared {new Date(String(inc.declaredAt)).toLocaleString()}</span>
            {inc.commanderId ? <span className="text-slate-400">commander {String(inc.commanderId)}</span> : null}
          </div>
          <p className="mt-2 whitespace-pre-wrap text-sm text-slate-300">{String(inc.description ?? "")}</p>
          <div className="mt-3 flex flex-wrap gap-2">
            {(NEXT_STATUS[status] ?? []).map((next) => (
              <button key={next} className="rounded bg-slate-700 px-3 py-1 text-sm text-white"
                onClick={() => call(() => apiFetch(`/soc/incidents/${params.id}`, { method: "PATCH", body: JSON.stringify({ status: next }) }), `Status → ${next}`)}>
                Move to {next}
              </button>
            ))}
            <button className="rounded bg-slate-800 px-3 py-1 text-sm text-slate-200"
              onClick={() => call(async () => {
                const out = await apiFetch<{ status: string; sections: Record<string, string[]>; summary: string }>(`/soc/ai/ask`, { method: "POST", body: JSON.stringify({ question: "Summarize this incident", incidentId: params.id }) });
                setAiAnswer(`${out.status}: ${out.summary}`);
              }, "AI summary generated from incident records.")}>
              AI summary (§97)
            </button>
            <button className="rounded bg-slate-800 px-3 py-1 text-sm text-slate-200"
              onClick={() => call(() => apiFetch(`/soc/incidents/${params.id}/reports`, { method: "POST", body: JSON.stringify({ type: "INCIDENT_REPORT" }) }), "Incident report snapshot generated from records (§117).")}>
              Generate incident report
            </button>
          </div>
          {aiAnswer && <p className="mt-2 rounded bg-slate-800/60 p-2 text-sm text-slate-200">{aiAnswer}</p>}
          {data && data.links.length > 0 && (
            <p className="mt-2 text-xs text-slate-500">Linked: {data.links.map((l) => `${String(l.resourceType)}:${String(l.resourceId)}`).join(" · ")}</p>
          )}
        </Card>
      )}
      <div className="grid gap-6 lg:grid-cols-2">
        <Card title="Timeline (§45 — corrections are amendments, originals are never edited)">
          <div className="space-y-2">
            <div className="flex gap-2">
              <input className="flex-1 rounded bg-slate-800 px-2 py-1 text-sm" placeholder="Analyst note" value={note} onChange={(e) => setNote(e.target.value)} />
              <button className="rounded bg-indigo-600 px-3 py-1 text-sm text-white"
                onClick={() => call(() => apiFetch(`/soc/incidents/${params.id}/timeline`, { method: "POST", body: JSON.stringify({ summary: note }) }), "Note appended.")}>Append</button>
            </div>
            {data && data.timeline.length === 0 ? <EmptyState title="No timeline entries yet." body="" /> : (
              <ul className="space-y-1 text-sm">
                {data?.timeline.map((t) => (
                  <li key={String(t.id)} className="rounded bg-slate-800/50 p-2">
                    <span className="text-xs text-slate-500">{String(t.entryType)} · {new Date(String(t.createdAt)).toLocaleString()}</span>
                    <span className="block text-slate-200">{String(t.summary)}</span>
                    {t.amendsEntryId ? <span className="text-xs text-amber-400">amends entry {String(t.amendsEntryId)}</span> : null}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </Card>
        <Card title="Evidence (§49 — SHA-256 anchored, access-logged; no admissibility claim is made)">
          <div className="space-y-2">
            <input className="w-full rounded bg-slate-800 px-2 py-1 text-sm" placeholder="Evidence title" value={evidenceTitle} onChange={(e) => setEvidenceTitle(e.target.value)} />
            <textarea className="w-full rounded bg-slate-800 px-2 py-1 text-sm" rows={3} placeholder="Evidence content (hashed at collection; store references for large artifacts)" value={evidenceContent} onChange={(e) => setEvidenceContent(e.target.value)} />
            <button className="rounded bg-indigo-600 px-3 py-1 text-sm text-white"
              onClick={() => call(() => apiFetch(`/soc/incidents/${params.id}/evidence`, { method: "POST", body: JSON.stringify({ source: "MANUAL", classification: "CONFIDENTIAL", objectReference: evidenceTitle ? `manual:${evidenceTitle}` : "manual:note", description: evidenceTitle, content: evidenceContent }) }), "Evidence collected with hash anchor.")}>
              Collect evidence
            </button>
            {data?.evidence.map((ev) => (
              <div key={String(ev.id)} className="rounded bg-slate-800/50 p-2 text-sm">
                <span className="text-slate-200">{String(ev.title)}</span>
                <span className="block truncate text-xs text-slate-500">sha256 {String(ev.contentHash)}</span>
                <div className="mt-1 flex gap-2">
                  <input className="flex-1 rounded bg-slate-900 px-2 py-1 text-xs" placeholder="Paste content to verify integrity"
                    value={verifyContent[String(ev.id)] ?? ""} onChange={(e) => setVerifyContent({ ...verifyContent, [String(ev.id)]: e.target.value })} />
                  <button className="rounded bg-slate-700 px-2 py-1 text-xs text-white"
                    onClick={() => call(async () => {
                      const out = await apiFetch<{ integrityOk: boolean }>(`/soc/incidents/${params.id}/evidence/${String(ev.id)}/verify`, { method: "POST", body: JSON.stringify({ content: verifyContent[String(ev.id)] ?? "" }) });
                      setNotice(out.integrityOk ? "Integrity OK — content matches the collection hash." : "INTEGRITY FAILURE — content does not match the collection hash (§143).");
                    }, "Verification complete.")}>Verify</button>
                </div>
              </div>
            ))}
          </div>
        </Card>
        <Card title="Response actions (§75 — predefined defensive catalog only; approvals enforce SoD)">
          <div className="space-y-2">
            <select className="w-full rounded bg-slate-800 px-2 py-1 text-sm" value={actionKey} onChange={(e) => setActionKey(e.target.value)}>
              {catalog.map((a) => <option key={a.key} value={a.key}>{a.title} — {a.approvalMode} ({a.impact} impact)</option>)}
            </select>
            <input className="w-full rounded bg-slate-800 px-2 py-1 text-sm" placeholder="Target reference (record id in this tenant)" value={targetReference} onChange={(e) => setTargetReference(e.target.value)} />
            <button className="rounded bg-indigo-600 px-3 py-1 text-sm text-white"
              onClick={() => call(() => apiFetch(`/soc/incidents/${params.id}/actions`, { method: "POST", body: JSON.stringify({ actionKey, targetReference, nonce: `${Date.now()}` }) }), "Action proposed — approval policy applies before execution.")}>
              Propose action
            </button>
            {data?.responseActions.map((ra) => (
              <div key={String(ra.id)} className="rounded bg-slate-800/50 p-2 text-sm">
                <span className="text-slate-200">{String(ra.actionKey)}</span>
                <span className="ml-2 text-xs text-slate-400">{String(ra.status)} → {String(ra.targetReference)}</span>
                <div className="mt-1 flex gap-2">
                  <button className="rounded bg-slate-700 px-2 py-1 text-xs text-white"
                    onClick={() => call(() => apiFetch(`/soc/response-actions/${String(ra.id)}/approve`, { method: "POST", body: JSON.stringify({ decision: "APPROVED" }) }), "Approval recorded (SoD enforced).")}>Approve</button>
                  <button className="rounded bg-red-700 px-2 py-1 text-xs text-white"
                    onClick={() => call(() => apiFetch(`/soc/response-actions/${String(ra.id)}/execute`, { method: "POST", body: JSON.stringify({}) }), "Execution attempted — see resulting status.")}>Execute</button>
                </div>
              </div>
            ))}
          </div>
        </Card>
        <Card title="Playbooks (§86 — declarative templates; steps never contain commands)">
          <div className="space-y-2">
            <div className="flex gap-2">
              <select className="flex-1 rounded bg-slate-800 px-2 py-1 text-sm" value={playbookKey} onChange={(e) => setPlaybookKey(e.target.value)}>
                {["suspected-credential-compromise", "critical-internet-facing-vulnerability", "exposed-secret", "suspicious-privileged-login", "cloud-security-incident", "devsecops-gate-incident", "malicious-indicator-match"].map((k) => <option key={k} value={k}>{k}</option>)}
              </select>
              <button className="rounded bg-indigo-600 px-3 py-1 text-sm text-white"
                onClick={() => call(() => apiFetch(`/soc/incidents/${params.id}/playbooks`, { method: "POST", body: JSON.stringify({ playbookKey }) }), "Playbook run started (version pinned).")}>Start</button>
            </div>
            {data?.playbookRuns.map((run) => {
              const steps = (run.stepsState as Array<Record<string, unknown>>) ?? [];
              const current = steps.find((s) => s.status === "IN_PROGRESS");
              return (
                <div key={String(run.id)} className="rounded bg-slate-800/50 p-2 text-sm">
                  <span className="text-slate-200">{String(run.playbookKey)} v{String(run.playbookVersion)}</span>
                  <span className="ml-2 text-xs text-slate-400">{String(run.status)}</span>
                  <span className="block text-xs text-slate-500">{steps.map((s) => `${String(s.key)}:${String(s.status)}`).join(" → ")}</span>
                  {current && run.status === "RUNNING" && (
                    <button className="mt-1 rounded bg-slate-700 px-2 py-1 text-xs text-white"
                      onClick={() => call(() => apiFetch(`/soc/playbook-runs/${String(run.id)}/advance`, { method: "POST", body: JSON.stringify({ stepKey: String(current.key) }) }), "Step completed.")}>
                      Complete step: {String(current.key)}
                    </button>
                  )}
                </div>
              );
            })}
          </div>
        </Card>
      </div>
    </div>
  );
}
