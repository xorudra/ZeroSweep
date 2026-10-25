"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@zerosweep/ui";

/**
 * Scan HTTP history (Prompt 8 §59/§60): every request/response a proxy
 * connector observed for this scan, with scope verdicts and integrity
 * hashes. The list shows metadata only; detail shows REDACTED copies
 * (credentials, cookies and tokens are masked by the evidence redactor);
 * raw-evidence references require Owner/Admin and are audit-logged.
 */

interface TxRow {
  id: string; method: string; url: string; host: string; statusCode?: number | null;
  source: string; scopeStatus: string; apiKind: string;
  requestHash?: string | null; responseHash?: string | null;
  requestSize?: number | null; responseSize?: number | null; observedAt: string;
}
interface TxDetail extends TxRow {
  requestRedacted?: string | null; responseRedacted?: string | null;
  requestArtifactRef?: string | null; responseArtifactRef?: string | null;
}
interface WsRow { id: string; url: string; origin?: string | null; subprotocol?: string | null; source: string }
interface RawView {
  requestArtifactRef?: string | null; responseArtifactRef?: string | null;
  requestHash?: string | null; responseHash?: string | null;
  requestRedacted?: string | null; responseRedacted?: string | null; note: string;
}

export default function HttpHistoryPage() {
  const params = useParams<{ id: string }>();
  const [txs, setTxs] = useState<TxRow[] | null>(null);
  const [wss, setWss] = useState<WsRow[]>([]);
  const [selected, setSelected] = useState<TxDetail | null>(null);
  const [raw, setRaw] = useState<RawView | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      const res = await apiFetch<{ transactions: TxRow[]; webSockets: WsRow[] }>(`/scans/${params.id}/http-history`);
      setTxs(res.transactions); setWss(res.webSockets);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not load HTTP history.");
    }
  }, [params.id]);
  useEffect(() => { void load(); }, [load]);

  const open = async (tx: TxRow) => {
    setRaw(null);
    try { setSelected(await apiFetch<TxDetail>(`/scans/${params.id}/http-history/${tx.id}`)); }
    catch (e) { setError(e instanceof ApiError ? e.message : "Could not load transaction."); }
  };

  const openRaw = async () => {
    if (!selected) return;
    setBusy(true);
    try {
      setRaw(await apiFetch<RawView>(`/scans/${params.id}/http-history/${selected.id}/raw`));
    } catch (e) {
      setError(e instanceof ApiError ? `${e.message} (raw evidence requires the Owner/Admin role and is audit-logged)` : "Raw evidence request failed.");
    } finally { setBusy(false); }
  };

  return (
    <>
      <PageHeader eyebrow="Scan / HTTP History" title="HTTP history & proxy evidence"
        body="Transactions observed by the ZAP / Burp / Caido connectors for this scan. Sensitive headers, cookies and tokens are redacted in display copies; raw bytes stay in object storage and are reachable only through an audited Owner/Admin access." />
      <p className="mb-4 text-sm"><Link href={`/scans/${params.id}`} className="text-sky-300 hover:underline">← Back to scan</Link></p>
      {error ? <Card><p className="text-sm text-red-300">{error}</p></Card> : null}
      {txs === null && !error ? <p className="text-sm text-slate-400">Loading…</p> : null}
      {txs !== null && txs.length === 0 ? (
        <EmptyState title="No proxy traffic recorded" body="No scanner connector observed HTTP traffic for this scan — passive analysis may have been skipped (no instance configured) or the target produced no proxy traffic." />
      ) : null}
      {txs !== null && txs.length > 0 ? (
        <Card>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="text-xs uppercase tracking-wide text-slate-500">
                  <th className="py-1 pr-3">Method</th><th className="py-1 pr-3">Host</th><th className="py-1 pr-3">Path</th>
                  <th className="py-1 pr-3">Status</th><th className="py-1 pr-3">Source</th><th className="py-1 pr-3">Scope</th>
                  <th className="py-1 pr-3">Kind</th><th className="py-1">Observed</th>
                </tr>
              </thead>
              <tbody>
                {txs.map((tx) => {
                  let path = tx.url;
                  try { const u = new URL(tx.url); path = u.pathname + u.search; } catch { /* keep raw */ }
                  return (
                    <tr key={tx.id} onClick={() => void open(tx)} className="cursor-pointer border-t border-slate-800 hover:bg-slate-900">
                      <td className="py-1.5 pr-3 text-slate-200">{tx.method}</td>
                      <td className="py-1.5 pr-3 text-slate-300">{tx.host}</td>
                      <td className="max-w-md truncate py-1.5 pr-3 text-slate-300">{path}</td>
                      <td className="py-1.5 pr-3 text-slate-300">{tx.statusCode ?? "—"}</td>
                      <td className="py-1.5 pr-3 text-slate-400">{tx.source}</td>
                      <td className="py-1.5 pr-3">{tx.scopeStatus === "IN_SCOPE" ? <Badge>IN SCOPE</Badge> : <span className="text-amber-300">{tx.scopeStatus}</span>}</td>
                      <td className="py-1.5 pr-3 text-slate-400">{tx.apiKind}</td>
                      <td className="py-1.5 text-slate-500">{new Date(tx.observedAt).toLocaleString()}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Card>
      ) : null}

      {wss.length > 0 ? (
        <Card title="WebSocket endpoints (inventory only)">
          <ul className="space-y-1 text-sm text-slate-300">
            {wss.map((ws) => (
              <li key={ws.id}>{ws.url}{ws.origin ? ` · origin ${ws.origin}` : ""}{ws.subprotocol ? ` · subprotocol ${ws.subprotocol}` : ""} · via {ws.source}</li>
            ))}
          </ul>
          <p className="mt-2 text-xs text-slate-500">WebSocket endpoints are inventoried for coverage; no WebSocket attack automation runs in this phase (§49).</p>
        </Card>
      ) : null}

      {selected ? (
        <Card title={`Transaction — ${selected.method} ${selected.url}`}>
          <p className="text-xs text-slate-500">
            Request SHA-256: {selected.requestHash ?? "—"} · Response SHA-256: {selected.responseHash ?? "—"} ·
            Sizes: {selected.requestSize ?? 0} / {selected.responseSize ?? 0} bytes · Artifact: {selected.requestArtifactRef ?? "—"}
          </p>
          <p className="mt-3 text-xs uppercase tracking-wide text-slate-500">Request (redacted)</p>
          <pre className="mt-1 max-h-64 overflow-auto whitespace-pre-wrap break-words rounded bg-slate-950 p-2 text-xs text-slate-300">{selected.requestRedacted ?? "No redacted copy stored."}</pre>
          <p className="mt-3 text-xs uppercase tracking-wide text-slate-500">Response (redacted)</p>
          <pre className="mt-1 max-h-64 overflow-auto whitespace-pre-wrap break-words rounded bg-slate-950 p-2 text-xs text-slate-300">{selected.responseRedacted ?? "No redacted copy stored."}</pre>
          <button disabled={busy} onClick={() => void openRaw()} className="mt-3 rounded bg-amber-600 px-3 py-1.5 text-sm text-white disabled:opacity-50">
            Raw evidence access (Owner/Admin · audited)
          </button>
          {raw ? (
            <div className="mt-3 rounded border border-amber-800 p-3 text-sm text-slate-300">
              <p>{raw.note}</p>
              <p className="mt-1 text-xs text-slate-400">Request artifact: {raw.requestArtifactRef ?? "—"} · Response artifact: {raw.responseArtifactRef ?? "—"}</p>
              <p className="text-xs text-slate-400">Hashes: {raw.requestHash ?? "—"} / {raw.responseHash ?? "—"}</p>
              <p className="mt-1 text-xs text-amber-300">This access has been recorded in the audit log (RAW_EVIDENCE_ACCESSED).</p>
            </div>
          ) : null}
        </Card>
      ) : null}
    </>
  );
}
