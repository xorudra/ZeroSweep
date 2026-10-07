"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { Badge, Card, EmptyState } from "@dsrclone/ui";
import { api, ApiError } from "@/lib/api-client";

type FindingDetail = Record<string, unknown> & {
  evidence?: Record<string, unknown>[];
  references?: Record<string, unknown>[];
  history?: Record<string, unknown>[];
  duplicates?: Record<string, unknown>[];
  sources?: string[];
  riskExplanation?: string[];
};

const REVIEW_TARGETS = ["CONFIRMED", "FALSE_POSITIVE", "ACCEPTED_RISK", "RESOLVED", "OPEN"];

function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div>
      <dt className="text-xs uppercase tracking-wide text-slate-500">{label}</dt>
      <dd className="mt-1 text-sm text-slate-200">{value ?? "—"}</dd>
    </div>
  );
}

/**
 * Finding detail (Prompt 7 §41): full normalized record, corroboration
 * panel (which tools reported it, with each tool's own evidence),
 * references, risk explanation, review history, and the manual validation
 * actions (§32). Evidence is rendered as plain text — React escapes it,
 * and it was redacted at ingestion (§30/§55).
 */
export default function Page() {
  const params = useParams<{ id: string }>();
  const [finding, setFinding] = useState<FindingDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [reviewStatus, setReviewStatus] = useState("CONFIRMED");
  const [notes, setNotes] = useState("");
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setFinding(await api.finding(params.id) as FindingDetail);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not load this finding.");
    }
  }, [params.id]);

  useEffect(() => { void load(); }, [load]);

  if (error) return <EmptyState title="Finding unavailable" body={error} />;
  if (!finding) return <p className="text-sm text-slate-400">Loading…</p>;

  const sources = Array.isArray(finding.sources) ? finding.sources : [];
  const evidence = finding.evidence ?? [];
  const references = finding.references ?? [];
  const history = finding.history ?? [];

  const submitReview = async () => {
    setBusy(true);
    setNotice(null);
    try {
      await api.reviewFinding(params.id, reviewStatus, notes);
      setNotes("");
      setNotice(`Review recorded: ${reviewStatus}. The original scanner evidence is unchanged.`);
      await load();
    } catch (e) {
      setNotice(e instanceof ApiError ? e.message : "Review failed.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <PageHeader eyebrow="Finding detail" title={String(finding.title ?? "Finding")} body={String(finding.description ?? "")} />
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <Badge tone={String(finding.severity ?? "")}>{String(finding.severity ?? "")}</Badge>
        <Badge>{`Status: ${String(finding.status ?? "")}`}</Badge>
        <Badge>{`Verification: ${String(finding.verificationStatus ?? "")}`}</Badge>
        {typeof finding.riskScore === "number" ? <Badge>{`Risk: ${finding.riskScore}/100 (${String(finding.riskBand ?? "")})`}</Badge> : null}
        <Link href="/findings" className="ml-auto text-sm text-sky-300 hover:underline">← All findings</Link>
      </div>

      <div className="grid gap-4 lg:grid-cols-2">
        <Card title="Normalized record">
          <dl className="grid grid-cols-2 gap-4">
            <Field label="Vulnerability class" value={String(finding.vulnClass ?? "—")} />
            <Field label="Confidence" value={`${String(finding.confidenceBand ?? "—")}${typeof finding.confidence === "number" ? ` (${finding.confidence.toFixed(2)})` : ""}`} />
            <Field label="Asset" value={String(finding.host ?? "—")} />
            <Field label="Endpoint" value={<span className="break-all">{String(finding.endpoint ?? "—")}</span>} />
            <Field label="Port / protocol" value={`${finding.port ?? "—"} / ${String(finding.protocol ?? "—")}`} />
            <Field label="Parameter" value={String(finding.parameter ?? "—")} />
            <Field label="CVE" value={finding.cve ? String(finding.cve) : "Not provided by source"} />
            <Field label="CWE" value={finding.cwe ? String(finding.cwe) : "—"} />
            <Field label="CVSS" value={typeof finding.cvssScore === "number" ? `${finding.cvssScore} ${String(finding.cvssVector ?? "")}` : "Not provided by source"} />
            <Field label="OWASP" value={String(finding.owaspCategory ?? "—")} />
            <Field label="First seen" value={finding.createdAt ? new Date(String(finding.createdAt)).toLocaleString() : "—"} />
            <Field label="Last seen" value={finding.updatedAt ? new Date(String(finding.updatedAt)).toLocaleString() : "—"} />
          </dl>
          {finding.technicalImpact ? <p className="mt-4 text-sm text-slate-300"><span className="text-slate-500">Technical impact: </span>{String(finding.technicalImpact)}</p> : null}
          {finding.remediation ? <p className="mt-2 text-sm text-slate-300"><span className="text-slate-500">Remediation: </span>{String(finding.remediation)}</p> : null}
          {Array.isArray(finding.riskExplanation) && finding.riskExplanation.length > 0 ? (
            <div className="mt-4">
              <p className="text-xs uppercase tracking-wide text-slate-500">Risk explanation (deterministic, §34)</p>
              <ul className="mt-1 list-disc pl-5 text-sm text-slate-300">
                {finding.riskExplanation.map((line, i) => <li key={i}>{line}</li>)}
              </ul>
            </div>
          ) : null}
        </Card>

        <Card title="Corroboration — contributing tools">
          {sources.length === 0 ? (
            <p className="text-sm text-slate-400">No contributing tools recorded.</p>
          ) : (
            <>
              <p className="text-sm text-slate-300">
                Reported by {sources.length} tool{sources.length === 1 ? "" : "s"}: {sources.join(", ")}.
                {sources.length > 1 ? " Independent tools agreeing on the same underlying issue raised this finding's confidence — each tool's own evidence is kept below." : ""}
              </p>
              <div className="mt-3 space-y-3">
                {evidence.map((e, i) => (
                  <div key={i} className="rounded-lg border border-slate-800 p-3">
                    <p className="text-sm font-medium text-slate-200">{String(e.sourceTool ?? "tool")}</p>
                    <p className="mt-1 whitespace-pre-wrap break-words text-sm text-slate-300">{String(e.summary ?? "")}</p>
                    {e.metadata && typeof e.metadata === "object" && "scannerProduct" in (e.metadata as Record<string, unknown>) ? (
                      <dl className="mt-2 grid grid-cols-2 gap-x-4 gap-y-1 text-xs text-slate-400 md:grid-cols-4">
                        <div>Source scanner: <span className="text-slate-200">{String((e.metadata as Record<string, unknown>).scannerProduct ?? "")}</span></div>
                        <div>Issue type: <span className="text-slate-200">{String((e.metadata as Record<string, unknown>).issueType ?? "—")}</span></div>
                        <div>Scanner confidence: <span className="text-slate-200">{String((e.metadata as Record<string, unknown>).confidenceLabel ?? "—")}</span></div>
                        <div>Scanner risk: <span className="text-slate-200">{String((e.metadata as Record<string, unknown>).scannerSeverity ?? "—")}</span></div>
                        {(e.metadata as Record<string, unknown>).scannerNotes ? (
                          <div className="md:col-span-4">Scanner notes: <span className="text-slate-300">{String((e.metadata as Record<string, unknown>).scannerNotes)}</span></div>
                        ) : null}
                      </dl>
                    ) : null}
                    {e.matchedAt ? <p className="mt-1 text-xs text-slate-500">Matched at: {String(e.matchedAt)}</p> : null}
                    {e.metadata && typeof e.metadata === "object" && "request" in (e.metadata as Record<string, unknown>) ? (
                      <pre className="mt-2 overflow-x-auto whitespace-pre-wrap break-words rounded bg-slate-950 p-2 text-xs text-slate-400">{String((e.metadata as Record<string, unknown>).request ?? "")}</pre>
                    ) : null}
                    {e.metadata && typeof e.metadata === "object" && "response" in (e.metadata as Record<string, unknown>) ? (
                      <pre className="mt-2 overflow-x-auto whitespace-pre-wrap break-words rounded bg-slate-950 p-2 text-xs text-slate-400">{String((e.metadata as Record<string, unknown>).response ?? "")}</pre>
                    ) : null}
                  </div>
                ))}
              </div>
            </>
          )}
          {references.length > 0 ? (
            <div className="mt-4">
              <p className="text-xs uppercase tracking-wide text-slate-500">References</p>
              <ul className="mt-1 space-y-1 text-sm">
                {references.map((r, i) => (
                  <li key={i}>
                    <a href={String(r.url)} target="_blank" rel="noreferrer" className="break-all text-sky-300 hover:underline">
                      {String(r.label ?? r.url)}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          ) : null}
        </Card>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <Card title="Review — manual validation (§32)">
          {finding.reviewedBy ? (
            <p className="mb-3 text-sm text-slate-300">
              Last reviewed by {String(finding.reviewedBy)} on {finding.reviewedAt ? new Date(String(finding.reviewedAt)).toLocaleString() : "—"}
              {finding.reviewNotes ? <> — “{String(finding.reviewNotes)}”</> : null}
            </p>
          ) : null}
          <div className="flex flex-col gap-3">
            <select
              className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200"
              value={reviewStatus} onChange={(e) => setReviewStatus(e.target.value)}
            >
              {REVIEW_TARGETS.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
            <textarea
              className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-2 text-sm text-slate-200"
              rows={3} value={notes} onChange={(e) => setNotes(e.target.value)}
              placeholder="Reason for this decision (required — recorded in the audit trail)"
            />
            <button
              className="rounded-lg bg-sky-600 px-4 py-2 text-sm font-medium text-white disabled:opacity-50"
              disabled={busy || notes.trim().length === 0} onClick={() => void submitReview()}
            >
              Record review
            </button>
            {notice ? <p className="text-sm text-slate-300">{notice}</p> : null}
          </div>
        </Card>

        <Card title="History — immutable lifecycle events (§37)">
          {history.length === 0 ? (
            <p className="text-sm text-slate-400">No history events yet.</p>
          ) : (
            <ul className="space-y-2 text-sm text-slate-300">
              {history.map((h, i) => (
                <li key={i} className="border-b border-slate-800 pb-2">
                  <span className="font-medium text-slate-100">{String(h.event ?? "")}</span>
                  {h.createdAt ? <span className="text-slate-500"> · {new Date(String(h.createdAt)).toLocaleString()}</span> : null}
                  {h.notes ? <p className="text-slate-400">{String(h.notes)}</p> : null}
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </>
  );
}
