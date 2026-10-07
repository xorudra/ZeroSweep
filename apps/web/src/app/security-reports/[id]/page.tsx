"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { PageHeader } from "@/components/Shell";
import { Badge, Card } from "@dsrclone/ui";
import { apiFetch } from "@/lib/api-client";

interface ReportDetail {
  id: string; title: string; type: string; status: string; approvalStatus: string;
  version: string; classification: string; createdAt: string; approvedBy?: string | null;
  snapshot?: { id: string; contentHash: string; findingCount: number; createdAt: string } | null;
  exports?: { id: string; format: string; status: string; checksum?: string | null; sizeBytes?: number | null }[];
}

const NEXT_APPROVAL: Record<string, string | undefined> = { DRAFT: "REVIEW", REVIEW: "APPROVED", APPROVED: "ISSUED" };

/** Report detail (Prompt 20 §56/§67/§70): snapshot identity, the
 *  approval chain and audited downloads. */
export default function SecurityReportDetailPage() {
  const params = useParams<{ id: string }>();
  const [report, setReport] = useState<ReportDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [downloadNote, setDownloadNote] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = () => apiFetch<ReportDetail>(`/security-reports/${params.id}`).then(setReport).catch((e: Error) => setError(e.message));
  useEffect(() => { load(); }, [params.id]);

  const approve = async () => {
    if (!report) return;
    const to = NEXT_APPROVAL[report.approvalStatus];
    if (!to) return;
    setBusy(true); setError(null);
    try {
      await apiFetch(`/security-reports/${report.id}/approval`, { method: "POST", body: JSON.stringify({ to }) });
      await load();
    } catch (e) { setError((e as Error).message); } finally { setBusy(false); }
  };

  const download = async (format: string) => {
    if (!report) return;
    setDownloadNote(null);
    try {
      const res = await apiFetch<{ status: string; note?: string; storageLocation?: string; checksum?: string }>(`/security-reports/${report.id}/download?format=${format}`);
      setDownloadNote(res.status === "READY"
        ? `${format} ready — storage: ${res.storageLocation} · sha256 ${res.checksum?.slice(0, 16)}… (download recorded in the audit log)`
        : `${format}: ${res.note ?? res.status}`);
    } catch (e) { setError((e as Error).message); }
  };

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Reporting" title={report?.title ?? "Report"} body="Immutable snapshot · approval chain · audited downloads" />
      {error ? <Card><p className="text-sm text-red-400">{error}</p></Card> : null}
      {!report ? <Card><p className="text-sm text-slate-400">Loading…</p></Card> : (
        <>
          <Card>
            <div className="flex flex-wrap items-center gap-2">
              <Badge tone="slate">{report.type}</Badge>
              <Badge tone="slate">{report.classification}</Badge>
              <Badge tone={report.status === "READY" ? "green" : "slate"}>{report.status}</Badge>
              <Badge tone="slate">approval: {report.approvalStatus}</Badge>
              <span className="text-xs text-slate-500">version {report.version}</span>
              {NEXT_APPROVAL[report.approvalStatus] ? (
                <span className="ml-auto"><button onClick={approve} disabled={busy} className="rounded bg-sky-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-sky-500 disabled:opacity-50">Move to {NEXT_APPROVAL[report.approvalStatus]}</button></span>
              ) : null}
            </div>
            <p className="mt-2 text-xs text-slate-500">Approval flow: DRAFT → REVIEW → APPROVED → ISSUED. An ISSUED report can never be regenerated in place.</p>
          </Card>
          <Card>
            <h3 className="mb-2 text-sm font-semibold text-slate-200">Snapshot</h3>
            {report.snapshot ? (
              <dl className="grid grid-cols-2 gap-2 text-sm text-slate-300">
                <div>Findings captured: <strong>{report.snapshot.findingCount}</strong></div>
                <div>Captured: {new Date(report.snapshot.createdAt).toLocaleString()}</div>
                <div className="col-span-2 break-all">SHA-256: <code className="text-xs">{report.snapshot.contentHash}</code></div>
              </dl>
            ) : (
              <p className="text-sm text-slate-500">No snapshot yet — generate the report to capture one from stored findings.</p>
            )}
          </Card>
          <Card>
            <h3 className="mb-2 text-sm font-semibold text-slate-200">Exports (PDF / HTML / JSON / CSV)</h3>
            {(report.exports ?? []).length === 0 ? (
              <p className="text-sm text-slate-500">No exports queued.</p>
            ) : (
              <ul className="space-y-2">
                {report.exports!.map((e) => (
                  <li key={e.id} className="flex items-center gap-3 text-sm">
                    <span className="w-12 text-slate-200">{e.format}</span>
                    <Badge tone={e.status === "READY" ? "green" : e.status === "FAILED" ? "red" : "slate"}>{e.status}</Badge>
                    {e.checksum ? <code className="text-xs text-slate-500">{e.checksum.slice(0, 16)}…</code> : null}
                    <span className="ml-auto"><button onClick={() => download(e.format)} className="rounded bg-sky-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-sky-500 disabled:opacity-50">Download</button></span>
                  </li>
                ))}
              </ul>
            )}
            {downloadNote ? <p className="mt-3 text-xs text-slate-400">{downloadNote}</p> : null}
          </Card>
        </>
      )}
    </div>
  );
}
