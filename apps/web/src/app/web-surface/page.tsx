"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState, StatCard } from "@zerosweep/ui";

/**
 * Web Surface (Prompt 6 §50): the discovered attack surface at a glance —
 * endpoints by type, provenance and status class, parameter inventory,
 * sensitive routes and JavaScript resources. Everything here is discovery
 * inventory: a SENSITIVE_ROUTE label (e.g. /admin) is a classification for
 * prioritization, never a vulnerability claim.
 */
interface EndpointRow {
  id: string;
  url: string;
  method: string;
  statusCode?: number | null;
  contentType?: string | null;
  endpointType?: string;
  classification?: string | null;
  source?: string | null;
  sources?: string[];
  scopeStatus?: string;
  parameterNames?: string[];
  asset?: { id: string; host: string } | null;
}

export default function Page() {
  const [state, setState] = useState<{ kind: "loading" } | { kind: "error"; message: string } | { kind: "ready"; items: EndpointRow[]; total: number }>({ kind: "loading" });

  useEffect(() => {
    let cancelled = false;
    apiFetch<{ items: EndpointRow[]; total: number }>(`/endpoints?pageSize=100`)
      .then((data) => { if (!cancelled) setState({ kind: "ready", items: data.items ?? [], total: data.total ?? 0 }); })
      .catch((e: unknown) => { if (!cancelled) setState({ kind: "error", message: e instanceof ApiError ? e.message : "Could not reach the API." }); });
    return () => { cancelled = true; };
  }, []);

  const stats = useMemo(() => {
    if (state.kind !== "ready") return null;
    const items = state.items;
    const byType: Record<string, number> = {};
    const bySource: Record<string, number> = {};
    const byStatus: Record<string, number> = {};
    let parameters = 0;
    for (const e of items) {
      byType[e.endpointType ?? "UNKNOWN"] = (byType[e.endpointType ?? "UNKNOWN"] ?? 0) + 1;
      for (const s of e.sources ?? (e.source ? [e.source] : [])) bySource[s] = (bySource[s] ?? 0) + 1;
      const cls = e.statusCode == null ? "unknown" : `${Math.floor(e.statusCode / 100)}xx`;
      byStatus[cls] = (byStatus[cls] ?? 0) + 1;
      parameters += (e.parameterNames ?? []).length;
    }
    return {
      total: state.total,
      api: byType.API ?? 0,
      sensitive: items.filter((e) => e.classification === "SENSITIVE_ROUTE").length,
      js: items.filter((e) => /\.m?js($|\?)/.test(e.url)).length,
      outOfScope: items.filter((e) => e.scopeStatus === "OUT_OF_SCOPE").length,
      parameters,
      byType, bySource, byStatus,
    };
  }, [state]);

  return (
    <>
      <PageHeader
        eyebrow="Web Surface"
        title="Web Surface"
        body="The merged crawl + content-discovery + parameter-discovery inventory. Routes are canonicalized and deduplicated with full provenance; out-of-scope routes are recorded, never scanned."
      />
      {state.kind === "loading" && <p className="text-sm text-slate-400">Loading…</p>}
      {state.kind === "error" && <EmptyState title="Nothing to show yet" body={`${state.message} When scans have discovered a web surface, it will appear here.`} />}
      {state.kind === "ready" && stats && (
        <div className="space-y-6">
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <StatCard label="Endpoints" value={stats.total} />
            <StatCard label="API endpoints" value={stats.api} />
            <StatCard label="Sensitive routes" value={stats.sensitive} hint="Classification label — not a finding" />
            <StatCard label="Parameters" value={stats.parameters} hint="Names only — values never stored" />
            <StatCard label="JavaScript resources" value={stats.js} />
            <StatCard label="Out of scope (recorded)" value={stats.outOfScope} />
          </div>
          <div className="grid gap-3 md:grid-cols-3">
            <Card title="By type">
              {Object.entries(stats.byType).map(([k, v]) => (
                <p key={k} className="text-sm text-slate-200">{k} <span className="text-slate-500">· {v}</span></p>
              ))}
              {Object.keys(stats.byType).length === 0 && <p className="text-sm text-slate-500">No endpoints yet.</p>}
            </Card>
            <Card title="By discovery source">
              {Object.entries(stats.bySource).map(([k, v]) => (
                <p key={k} className="text-sm text-slate-200">{k} <span className="text-slate-500">· {v}</span></p>
              ))}
              {Object.keys(stats.bySource).length === 0 && <p className="text-sm text-slate-500">No provenance yet.</p>}
            </Card>
            <Card title="By status class">
              {Object.entries(stats.byStatus).map(([k, v]) => (
                <p key={k} className="text-sm text-slate-200">{k} <span className="text-slate-500">· {v}</span></p>
              ))}
              {Object.keys(stats.byStatus).length === 0 && <p className="text-sm text-slate-500">No responses recorded.</p>}
            </Card>
          </div>
          <Card title="Endpoints">
            <div className="space-y-1">
              {state.items.map((e) => (
                <p key={e.id} className="break-all text-sm text-slate-200">
                  <span className="text-slate-400">{e.method}</span>{" "}
                  <Link href={`/endpoints/${e.id}`} className="text-sky-300 hover:underline">{e.url}</Link>
                  <span className="text-slate-500">
                    {" "}· {e.endpointType ?? "UNKNOWN"} · {e.statusCode ?? "—"}
                    {e.classification ? ` · ${e.classification}` : ""}
                    {(e.sources ?? []).length ? ` · via ${[...new Set(e.sources ?? [])].join(", ")}` : ""}
                  </span>{" "}
                  <Badge>{e.scopeStatus ?? "—"}</Badge>
                </p>
              ))}
              {state.items.length === 0 && <p className="text-sm text-slate-500">No endpoints discovered yet.</p>}
            </div>
          </Card>
        </div>
      )}
    </>
  );
}
