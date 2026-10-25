"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, EmptyState } from "@zerosweep/ui";

/**
 * Endpoint inventory (Prompt 5 §45): every URL discovered by authorized
 * scans — normalized URL, host, method, status, parameter NAMES (values are
 * never stored for sensitive parameters), source tool and scope status.
 * Out-of-scope URLs are third-party references: shown, never scanned.
 */
interface EndpointRow {
  id: string;
  url: string;
  method: string;
  statusCode?: number | null;
  parameterNames?: string[];
  source?: string | null;
  sources?: string[];
  scopeStatus?: string;
  contentType?: string | null;
  endpointType?: string;
  classification?: string | null;
  asset?: { id: string; host: string } | null;
}

const selectCls = "rounded bg-slate-900 px-2 py-1.5 text-sm text-slate-200 border border-slate-700";

export default function Page() {
  const [scopeStatus, setScopeStatus] = useState("");
  const [endpointType, setEndpointType] = useState("");
  const [search, setSearch] = useState("");
  const [state, setState] = useState<{ kind: "loading" } | { kind: "error"; message: string } | { kind: "ready"; items: EndpointRow[]; total: number }>({ kind: "loading" });

  useEffect(() => {
    let cancelled = false;
    const params = new URLSearchParams({ pageSize: "50" });
    if (scopeStatus) params.set("scopeStatus", scopeStatus);
    if (endpointType) params.set("endpointType", endpointType);
    if (search) params.set("search", search);
    setState({ kind: "loading" });
    apiFetch<{ items: EndpointRow[]; total: number }>(`/endpoints?${params.toString()}`)
      .then((data) => { if (!cancelled) setState({ kind: "ready", items: data.items ?? [], total: data.total ?? 0 }); })
      .catch((e: unknown) => { if (!cancelled) setState({ kind: "error", message: e instanceof ApiError ? e.message : "Could not reach the API." }); });
    return () => { cancelled = true; };
  }, [scopeStatus, endpointType, search]);

  return (
    <>
      <PageHeader eyebrow="Endpoints" title="Endpoints" body="URLs discovered by authorized scans — historical archives, probing and scoped crawling. Parameter values of sensitive parameters are redacted before storage." />
      <div className="mb-4 flex flex-wrap gap-2">
        <select aria-label="Scope status" className={selectCls} value={scopeStatus} onChange={(e) => setScopeStatus(e.target.value)}>
          <option value="">All scope statuses</option>
          <option value="IN_SCOPE">In scope</option>
          <option value="OUT_OF_SCOPE">Out of scope (references)</option>
        </select>
        <select aria-label="Endpoint type" className={selectCls} value={endpointType} onChange={(e) => setEndpointType(e.target.value)}>
          <option value="">All types</option>
          {["PAGE", "DIRECTORY", "FILE", "API", "STATIC", "UNKNOWN"].map((t) => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
        <input aria-label="Search URLs" className={selectCls} placeholder="Search URLs" value={search} onChange={(e) => setSearch(e.target.value)} />
      </div>
      {state.kind === "loading" && <p className="text-sm text-slate-400">Loading…</p>}
      {state.kind === "error" && <EmptyState title="Nothing to show yet" body={`${state.message} When the API is running and scans have discovered endpoints, they will appear here.`} />}
      {state.kind === "ready" && state.items.length === 0 && (
        <EmptyState title="No endpoints yet" body="Endpoints appear after URL discovery, probing or crawling stages of an authorized scan." />
      )}
      {state.kind === "ready" && state.items.length > 0 && (
        <div className="overflow-x-auto rounded-xl border border-slate-800">
          <table className="w-full min-w-[900px] text-left text-sm">
            <thead className="bg-slate-900/70 text-slate-400">
              <tr>
                {["URL", "Host", "Method", "Status", "Type", "Content-Type", "Parameters", "Sources", "Scope"].map((c) => (
                  <th key={c} className="px-4 py-3 font-medium">{c}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {state.items.map((e) => (
                <tr key={e.id} className="border-t border-slate-800">
                  <td className="max-w-md break-all px-4 py-3 text-slate-200">
                    <Link href={`/endpoints/${e.id}`} className="text-sky-300 hover:underline">{e.url}</Link>
                    {e.classification ? <span className="text-amber-300"> · {e.classification}</span> : null}
                  </td>
                  <td className="px-4 py-3">{e.asset ? <Link href={`/assets/${e.asset.id}`} className="text-sky-300 hover:underline">{e.asset.host}</Link> : "—"}</td>
                  <td className="px-4 py-3 text-slate-200">{e.method}</td>
                  <td className="px-4 py-3 text-slate-200">{e.statusCode ?? "—"}</td>
                  <td className="px-4 py-3 text-slate-200">{e.endpointType ?? "UNKNOWN"}</td>
                  <td className="px-4 py-3 text-slate-200">{e.contentType ?? "—"}</td>
                  <td className="px-4 py-3 text-slate-200">{(e.parameterNames ?? []).join(", ") || "—"}</td>
                  <td className="px-4 py-3 text-slate-200">{[...new Set([...(e.sources ?? []), ...(e.source ? [e.source] : [])])].join(", ") || "—"}</td>
                  <td className="px-4 py-3"><Badge>{e.scopeStatus ?? "—"}</Badge></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {state.kind === "ready" && <p className="mt-3 text-xs text-slate-500">{state.total} endpoint(s)</p>}
    </>
  );
}
