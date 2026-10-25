"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, EmptyState } from "@zerosweep/ui";

/**
 * Asset inventory (Prompt 5 §43). Assets are discovered ONLY by authorized
 * scans: hostnames, IPs, scope verdicts, HTTP status, technologies and the
 * tools that found them (provenance). Filters are server-side; out-of-scope
 * discoveries are shown with their verdict — they are never promoted into
 * scan targets.
 */
interface AssetRow {
  id: string;
  host: string;
  ip?: string | null;
  type: string;
  scopeStatus: string;
  httpStatus?: number | null;
  sources?: string[];
  firstSeen?: string;
  lastSeen?: string;
  technologies?: { name: string }[];
  _count?: { services: number; endpoints: number };
}

const selectCls = "rounded bg-slate-900 px-2 py-1.5 text-sm text-slate-200 border border-slate-700";

export default function Page() {
  const [scopeStatus, setScopeStatus] = useState("");
  const [technology, setTechnology] = useState("");
  const [source, setSource] = useState("");
  const [search, setSearch] = useState("");
  const [state, setState] = useState<{ kind: "loading" } | { kind: "error"; message: string } | { kind: "ready"; items: AssetRow[]; total: number }>({ kind: "loading" });

  useEffect(() => {
    let cancelled = false;
    const params = new URLSearchParams({ pageSize: "50" });
    if (scopeStatus) params.set("scopeStatus", scopeStatus);
    if (technology) params.set("technology", technology);
    if (source) params.set("source", source);
    if (search) params.set("search", search);
    setState({ kind: "loading" });
    apiFetch<{ items: AssetRow[]; total: number }>(`/assets?${params.toString()}`)
      .then((data) => { if (!cancelled) setState({ kind: "ready", items: data.items ?? [], total: data.total ?? 0 }); })
      .catch((e: unknown) => { if (!cancelled) setState({ kind: "error", message: e instanceof ApiError ? e.message : "Could not reach the API." }); });
    return () => { cancelled = true; };
  }, [scopeStatus, technology, source, search]);

  return (
    <>
      <PageHeader eyebrow="Assets" title="Assets" body="Hosts discovered by authorized scans, with scope verdicts, technologies and provenance. Out-of-scope assets are recorded for visibility and are never scanned." />
      <div className="mb-4 flex flex-wrap gap-2">
        <select aria-label="Scope status" className={selectCls} value={scopeStatus} onChange={(e) => setScopeStatus(e.target.value)}>
          <option value="">All scope statuses</option>
          <option value="IN_SCOPE">In scope</option>
          <option value="OUT_OF_SCOPE">Out of scope</option>
          <option value="PENDING_REVIEW">Pending review</option>
        </select>
        <input aria-label="Technology filter" className={selectCls} placeholder="Technology (e.g. nginx)" value={technology} onChange={(e) => setTechnology(e.target.value)} />
        <input aria-label="Source filter" className={selectCls} placeholder="Source tool (e.g. subfinder)" value={source} onChange={(e) => setSource(e.target.value)} />
        <input aria-label="Search hosts" className={selectCls} placeholder="Search hosts" value={search} onChange={(e) => setSearch(e.target.value)} />
      </div>
      {state.kind === "loading" && <p className="text-sm text-slate-400">Loading…</p>}
      {state.kind === "error" && <EmptyState title="Nothing to show yet" body={`${state.message} When the API is running and scans have discovered assets, they will appear here.`} />}
      {state.kind === "ready" && state.items.length === 0 && (
        <EmptyState title="No assets yet" body="Assets are discovered by scans of verified targets. Nothing matches the current filters." />
      )}
      {state.kind === "ready" && state.items.length > 0 && (
        <div className="overflow-x-auto rounded-xl border border-slate-800">
          <table className="w-full min-w-[900px] text-left text-sm">
            <thead className="bg-slate-900/70 text-slate-400">
              <tr>
                {["Hostname", "IP", "Type", "Scope Status", "HTTP Status", "Technologies", "Sources", "First Seen", "Last Seen"].map((c) => (
                  <th key={c} className="px-4 py-3 font-medium">{c}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {state.items.map((a) => (
                <tr key={a.id} className="border-t border-slate-800">
                  <td className="px-4 py-3"><Link href={`/assets/${a.id}`} className="text-sky-300 hover:underline">{a.host}</Link></td>
                  <td className="px-4 py-3 text-slate-200">{a.ip ?? "—"}</td>
                  <td className="px-4 py-3 text-slate-200">{a.type}</td>
                  <td className="px-4 py-3"><Badge>{a.scopeStatus}</Badge></td>
                  <td className="px-4 py-3 text-slate-200">{a.httpStatus ?? "—"}</td>
                  <td className="px-4 py-3 text-slate-200">{(a.technologies ?? []).map((t) => t.name).slice(0, 3).join(", ") || "—"}</td>
                  <td className="px-4 py-3 text-slate-200">{(a.sources ?? []).join(", ") || "—"}</td>
                  <td className="px-4 py-3 text-slate-400">{a.firstSeen ? new Date(a.firstSeen).toLocaleDateString() : "—"}</td>
                  <td className="px-4 py-3 text-slate-400">{a.lastSeen ? new Date(a.lastSeen).toLocaleDateString() : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      {state.kind === "ready" && <p className="mt-3 text-xs text-slate-500">{state.total} asset(s)</p>}
    </>
  );
}
