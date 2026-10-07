"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { Badge, Card, EmptyState } from "@dsrclone/ui";
import { apiFetch, ApiError } from "@/lib/api-client";

type Detail = Record<string, unknown> & {
  intelligence?: {
    hasData: boolean; cve?: Record<string, unknown> | null; epss?: Record<string, unknown> | null;
    kev?: Record<string, unknown> | null; notes?: string[]; noDataMessage?: string;
    cvssTrust?: { scannerScore?: number; intelligenceScore?: number; effectiveScore?: number; reason: string };
  };
  observations?: Record<string, unknown>[];
  comments?: Record<string, unknown>[];
  history?: Record<string, unknown>[];
  retests?: Record<string, unknown>[];
  exploitReferences?: Record<string, unknown>[];
  riskFactors?: string[];
  riskAcceptance?: { reason: string; acceptedBy?: string; expiresAt?: string } | null;
};

const TRANSITIONS = ["TRIAGED", "CONFIRMED", "IN_PROGRESS", "REMEDIATED", "RESOLVED", "NEW"];
const inputCls = "w-full rounded bg-slate-900 px-2 py-1.5 text-sm text-slate-100 outline-none ring-slate-700 focus:ring-1";
const labelCls = "block text-xs uppercase tracking-wide text-slate-500";

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wide text-slate-500">{label}</dt>
      <dd className="mt-1 text-sm text-slate-200">{value ?? "—"}</dd>
    </div>
  );
}

/**
 * Vulnerability detail (Prompt 11 §67): description + evidence summary,
 * affected asset/service, source observations with per-scanner severity
 * preserved (§63), CVE/CWE/CPE, CVSS trust view (§32), EPSS/KEV only when
 * the local dataset holds them, risk factor explanation (§38), lifecycle,
 * assignment, SLA, remediation guidance, retest history, comments and the
 * full audit-backed history. Actions go through the permission-checked
 * API — the buttons never imply a permission the API would deny.
 */
export default function Page() {
  const params = useParams<{ id: string }>();
  const [vuln, setVuln] = useState<Detail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [transition, setTransition] = useState("TRIAGED");
  const [reason, setReason] = useState("");
  const [assignee, setAssignee] = useState("");
  const [comment, setComment] = useState("");
  const [acceptExpiry, setAcceptExpiry] = useState("");

  const load = useCallback(async () => {
    try {
      setVuln(await apiFetch<Detail>(`/vulnerabilities/${params.id}`));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not load this vulnerability.");
    }
  }, [params.id]);
  useEffect(() => { void load(); }, [load]);

  if (error) return <EmptyState title="Vulnerability unavailable" body={error} />;
  if (!vuln) return <p className="text-sm text-slate-400">Loading…</p>;

  const act = async (fn: () => Promise<unknown>, ok: string) => {
    setBusy(true); setNotice(null);
    try { await fn(); setNotice(ok); await load(); }
    catch (e) { setNotice(e instanceof ApiError ? e.message : "Action failed."); }
    finally { setBusy(false); }
  };
  const post = (path: string, body?: unknown) => apiFetch(path, { method: "POST", body: body === undefined ? undefined : JSON.stringify(body) });

  const intel = vuln.intelligence;
  return (
    <>
      <PageHeader eyebrow="Vulnerability Management" title={String(vuln.title ?? "Vulnerability")} body={String(vuln.description ?? "")} />
      {notice ? <p className="mb-4 rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200">{notice}</p> : null}
      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <dl className="grid grid-cols-2 gap-4 md:grid-cols-3">
            <Field label="Priority" value={vuln.priority ? <Badge tone={String(vuln.priority)}>{String(vuln.priority)}</Badge> : "—"} />
            <Field label="Severity" value={<Badge tone={String(vuln.severity ?? "")}>{String(vuln.severity ?? "")}</Badge>} />
            <Field label="Lifecycle" value={String(vuln.lifecycleStatus ?? "")} />
            <Field label="Detection" value={String(vuln.detectionKind ?? "")} />
            <Field label="Asset" value={vuln.host ? `${String(vuln.host)}${vuln.port ? `:${String(vuln.port)}` : ""}` : "—"} />
            <Field label="Endpoint" value={vuln.endpoint ? String(vuln.endpoint) : "—"} />
            <Field label="CVE" value={vuln.cve ? <Link href={`/vulnerabilities/cve/${String(vuln.cve)}`} className="text-sky-300 hover:underline">{String(vuln.cve)}</Link> : "—"} />
            <Field label="CWE" value={vuln.cwe ? String(vuln.cwe) : "—"} />
            <Field label="CPE" value={vuln.cpe ? String(vuln.cpe) : "—"} />
            <Field label="Sources" value={Array.isArray(vuln.sources) ? vuln.sources.join(", ") : "—"} />
            <Field label="Owner" value={String(vuln.assignedToId ?? vuln.assignedToTeam ?? "Unassigned")} />
            <Field label="SLA" value={`${String(vuln.slaStatus ?? "")}${vuln.dueAt ? ` — due ${new Date(String(vuln.dueAt)).toLocaleDateString()}` : ""}`} />
            <Field label="First / Last Seen" value={`${vuln.firstSeen ? new Date(String(vuln.firstSeen)).toLocaleDateString() : "—"} / ${vuln.lastSeen ? new Date(String(vuln.lastSeen)).toLocaleDateString() : "—"}`} />
            <Field label="Recurrences" value={String(vuln.recurrenceCount ?? 0)} />
            <Field label="Remediation group" value={typeof vuln.remediationGroup === "object" && vuln.remediationGroup ? String((vuln.remediationGroup as { label?: string }).label ?? "") : "—"} />
          </dl>
          <h3 className="mt-6 text-sm font-semibold text-slate-200">Remediation guidance</h3>
          <p className="mt-1 text-sm text-slate-400">{String(vuln.remediation ?? "No tool- or analyst-provided remediation recorded — DSRclone never fabricates fixes (§52).")}</p>
          {vuln.riskAcceptance ? (
            <p className="mt-3 rounded-lg border border-amber-800 bg-amber-950/40 px-3 py-2 text-sm text-amber-200">
              Risk accepted by {vuln.riskAcceptance.acceptedBy ?? "—"} until {vuln.riskAcceptance.expiresAt ? new Date(vuln.riskAcceptance.expiresAt).toLocaleDateString() : "—"}: {vuln.riskAcceptance.reason}
            </p>
          ) : null}
        </Card>

        <Card>
          <h3 className="text-sm font-semibold text-slate-200">Risk explanation (§38)</h3>
          <p className="mt-1 text-sm text-slate-400">Score {String(vuln.riskScore ?? "—")} · band {String(vuln.riskBand ?? "—")}</p>
          <ul className="mt-2 list-disc space-y-1 pl-5 text-sm text-slate-400">
            {(vuln.riskFactors ?? []).map((f, i) => <li key={i}>{f}</li>)}
            {(vuln.riskFactors ?? []).length === 0 ? <li>Factors are recorded when Risk Engine V2 evaluates this finding.</li> : null}
          </ul>
          <h3 className="mt-5 text-sm font-semibold text-slate-200">Intelligence</h3>
          {intel?.hasData ? (
            <dl className="mt-2 space-y-2 text-sm text-slate-300">
              {intel.epss ? <div>EPSS {(intel.epss.score as number)?.toFixed?.(3) ?? String(intel.epss.score)} · percentile {(intel.epss.percentile as number)?.toFixed?.(3) ?? String(intel.epss.percentile)} <span className="text-slate-500">(probability of exploitation — context, not severity)</span></div> : null}
              {intel.kev ? <div><Badge tone="CRITICAL">CISA KEV</Badge> <span className="text-slate-400">listed {String(intel.kev.dateAdded ?? "")}</span></div> : null}
              {intel.cvssTrust ? <div className="text-slate-400">{intel.cvssTrust.reason}</div> : null}
            </dl>
          ) : (
            <p className="mt-2 text-sm text-slate-500">{intel?.noDataMessage ?? "no intelligence data — the governed local dataset holds no record for this finding's identifiers. Nothing is inferred or filled in."}</p>
          )}
          {(vuln.exploitReferences ?? []).length > 0 ? (
            <>
              <h4 className="mt-4 text-xs uppercase tracking-wide text-slate-500">Public exploit references (§20)</h4>
              <ul className="mt-1 space-y-1 text-sm">
                {(vuln.exploitReferences ?? []).map((r, i) => (
                  <li key={i}><a className="text-sky-300 hover:underline" href={String(r.reference)} target="_blank" rel="noreferrer">{String(r.title)}</a> <span className="text-slate-500">— a reference exists; this is NOT confirmation the issue is exploitable here.</span></li>
                ))}
              </ul>
            </>
          ) : null}
          <button disabled={busy} onClick={() => void act(() => post(`/vulnerabilities/${params.id}/enrich`), "Enrichment re-evaluated against the local dataset.")}
            className="mt-4 rounded-lg bg-sky-600 px-3 py-1.5 text-sm text-white disabled:opacity-50">Re-run enrichment</button>
        </Card>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <Card>
          <h3 className="text-sm font-semibold text-slate-200">Lifecycle & ownership</h3>
          <div className="mt-3 space-y-3">
            <div>
              <label className={labelCls}>Transition</label>
              <div className="flex gap-2">
                <select className={inputCls} value={transition} onChange={(e) => setTransition(e.target.value)}>
                  {TRANSITIONS.map((t) => <option key={t} value={t}>{t}</option>)}
                </select>
                <button disabled={busy} className="rounded-lg bg-slate-700 px-3 py-1.5 text-sm text-white disabled:opacity-50"
                  onClick={() => void act(() => apiFetch(`/vulnerabilities/${params.id}`, { method: "PATCH", body: JSON.stringify({ lifecycleStatus: transition, reason: reason || undefined }) }), `Transition recorded: ${transition}.`)}>Apply</button>
              </div>
            </div>
            <div>
              <label className={labelCls}>Reason (required for false positive / risk acceptance)</label>
              <input className={inputCls} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="Why is this changing?" />
            </div>
            <div className="flex flex-wrap gap-2">
              <button disabled={busy} className="rounded-lg bg-slate-700 px-3 py-1.5 text-sm text-white disabled:opacity-50"
                onClick={() => void act(() => post(`/vulnerabilities/${params.id}/false-positive`, { reason }), "Marked false positive — evidence preserved.")}>Mark false positive</button>
              <input type="date" className="rounded bg-slate-900 px-2 py-1.5 text-sm text-slate-100" value={acceptExpiry} onChange={(e) => setAcceptExpiry(e.target.value)} aria-label="Risk acceptance expiry" />
              <button disabled={busy || !acceptExpiry} className="rounded-lg bg-slate-700 px-3 py-1.5 text-sm text-white disabled:opacity-50"
                onClick={() => void act(() => post(`/vulnerabilities/${params.id}/accept-risk`, { reason, expiresAt: new Date(acceptExpiry).toISOString() }), "Risk accepted with expiry.")}>Accept risk</button>
              <button disabled={busy} className="rounded-lg bg-slate-700 px-3 py-1.5 text-sm text-white disabled:opacity-50"
                onClick={() => void act(() => post(`/vulnerabilities/${params.id}/request-retest`, { reason: reason || undefined }), "Targeted retest requested — the worker re-runs the original check under the same gates.")}>Request retest</button>
            </div>
            <div>
              <label className={labelCls}>Assign (user id or team)</label>
              <div className="flex gap-2">
                <input className={inputCls} value={assignee} onChange={(e) => setAssignee(e.target.value)} placeholder="user id or team name" />
                <button disabled={busy} className="rounded-lg bg-slate-700 px-3 py-1.5 text-sm text-white disabled:opacity-50"
                  onClick={() => void act(() => post(`/vulnerabilities/${params.id}/assign`, { assignedToId: assignee || null }), "Assignment recorded.")}>Assign</button>
              </div>
            </div>
          </div>
        </Card>

        <Card>
          <h3 className="text-sm font-semibold text-slate-200">Comments (§45)</h3>
          <ul className="mt-2 space-y-2 text-sm text-slate-300">
            {(vuln.comments ?? []).map((c, i) => (
              <li key={i} className="rounded-lg bg-slate-900 px-3 py-2">
                <span className="text-slate-500">{String(c.authorId ?? "")} · {c.createdAt ? new Date(String(c.createdAt)).toLocaleString() : ""}</span>
                <p>{String(c.text ?? "")}</p>
              </li>
            ))}
            {(vuln.comments ?? []).length === 0 ? <li className="text-slate-500">No comments yet.</li> : null}
          </ul>
          <div className="mt-3 flex gap-2">
            <input className={inputCls} value={comment} onChange={(e) => setComment(e.target.value)} placeholder="Add a comment (sanitized, audited)" />
            <button disabled={busy || !comment} className="rounded-lg bg-sky-600 px-3 py-1.5 text-sm text-white disabled:opacity-50"
              onClick={() => void act(() => post(`/vulnerabilities/${params.id}/comments`, { body: comment }), "Comment added.")}>Post</button>
          </div>
        </Card>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <Card>
          <h3 className="text-sm font-semibold text-slate-200">Scanner observations (§59–§64)</h3>
          <p className="text-xs text-slate-500">One canonical vulnerability, many observations. Per-scanner severities are preserved — conflicts are never averaged away (§63).</p>
          <ul className="mt-2 space-y-1 text-sm text-slate-300">
            {(vuln.observations ?? []).map((o, i) => (
              <li key={i}>{String(o.sourceTool)} · severity {String(o.severity)} · {o.observedAt ? new Date(String(o.observedAt)).toLocaleString() : ""}</li>
            ))}
            {(vuln.observations ?? []).length === 0 ? <li className="text-slate-500">No separate observation records yet — observations are recorded as scans correlate.</li> : null}
          </ul>
          <h3 className="mt-5 text-sm font-semibold text-slate-200">Retests (§55)</h3>
          <ul className="mt-2 space-y-1 text-sm text-slate-300">
            {(vuln.retests ?? []).map((r, i) => (
              <li key={i}>{String(r.sourceTool)} · {String(r.status)}{r.result ? ` → ${String(r.result)}` : ""} · {r.createdAt ? new Date(String(r.createdAt)).toLocaleString() : ""}</li>
            ))}
            {(vuln.retests ?? []).length === 0 ? <li className="text-slate-500">No retests requested yet.</li> : null}
          </ul>
        </Card>
        <Card>
          <h3 className="text-sm font-semibold text-slate-200">History (§47)</h3>
          <ul className="mt-2 space-y-1 text-sm text-slate-300">
            {(vuln.history ?? []).map((h, i) => (
              <li key={i}>{String(h.event)} <span className="text-slate-500">· {h.createdAt ? new Date(String(h.createdAt)).toLocaleString() : ""}{h.actorId ? ` · ${String(h.actorId)}` : ""}</span>{h.notes ? <p className="text-slate-400">{String(h.notes)}</p> : null}</li>
            ))}
            {(vuln.history ?? []).length === 0 ? <li className="text-slate-500">No history recorded yet.</li> : null}
          </ul>
        </Card>
      </div>
    </>
  );
}
