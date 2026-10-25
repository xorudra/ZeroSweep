"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { api, apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@zerosweep/ui";

/**
 * Asset detail (Prompt 5 §44): canonical hostname, addresses, scope verdict,
 * services, technologies, endpoints, discovery sources and scan history.
 * Raw scanner output is never shown here — normalized inventory only.
 */
interface AssetDetail {
  id: string;
  host: string;
  ip?: string | null;
  type: string;
  scopeStatus: string;
  httpStatus?: number | null;
  sources?: string[];
  firstSeen?: string;
  lastSeen?: string;
  discoveredByScanId?: string | null;
  target?: { id: string; value: string; type: string } | null;
  services?: { id: string; port: number; protocol: string; name?: string | null; product?: string | null; version?: string | null }[];
  technologies?: { id: string; name: string; version?: string | null; category?: string | null; source?: string | null; confidence?: number | null }[];
  endpoints?: { id: string; url: string; method: string; statusCode?: number | null; parameterNames?: string[]; source?: string | null; scopeStatus?: string }[];
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
      <div className="mt-1 text-sm text-slate-200">{children}</div>
    </div>
  );
}

interface AssetRisk {
  openCount: number; worstRiskScore: number; kevCount: number; overdueCount: number;
  findings: { id: string; title: string; severity: string; priority?: string | null; lifecycleStatus: string }[];
}

interface WebSurfaceSummary {
  totalEndpoints: number;
  apiEndpoints: number;
  sensitiveRoutes: number;
  javascriptResources: number;
  parametersDiscovered: number;
  endpointsWithParameters: number;
  formsDiscovered: number;
  endpointsBySource?: Record<string, number>;
  endpointsByType?: Record<string, number>;
}

export default function Page() {
  const params = useParams<{ id: string }>();
  const [state, setState] = useState<{ kind: "loading" } | { kind: "error"; message: string } | { kind: "ready"; asset: AssetDetail }>({ kind: "loading" });
  const [surface, setSurface] = useState<WebSurfaceSummary | null>(null);
  const [risk, setRisk] = useState<AssetRisk | null>(null);

  useEffect(() => {
    let cancelled = false;
    apiFetch<AssetDetail>(`/assets/${params.id}`)
      .then((asset) => { if (!cancelled) setState({ kind: "ready", asset }); })
      .catch((e: unknown) => { if (!cancelled) setState({ kind: "error", message: e instanceof ApiError ? e.message : "Could not reach the API." }); });
    // Web-surface summary is best-effort (Prompt 6 §55).
    api.assetWebSurface(params.id).then((s) => { if (!cancelled) setSurface(s as WebSurfaceSummary); }).catch(() => undefined);
    // Vulnerability risk summary (Prompt 11 §70) — best-effort like the surface summary.
    apiFetch<AssetRisk>(`/vulnerabilities/by-asset/${params.id}/risk`).then((r) => { if (!cancelled) setRisk(r); }).catch(() => undefined);
    return () => { cancelled = true; };
  }, [params.id]);

  if (state.kind === "loading") return <p className="text-sm text-slate-400">Loading…</p>;
  if (state.kind === "error") return <EmptyState title="Asset not found" body={state.message} />;
  const a = state.asset;
  return (
    <>
      <PageHeader eyebrow="Asset" title={a.host} body="Normalized inventory for this asset. Out-of-scope assets are never promoted into scan targets." />
      <p className="mb-4 text-sm"><Link href="/assets" className="text-sky-300 hover:underline">← All assets</Link></p>
      <div className="space-y-6">
        <Card title="Overview">
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <Field label="Canonical hostname">{a.host}</Field>
            <Field label="IP address">{a.ip ?? "Not resolved"}</Field>
            <Field label="Type">{a.type}</Field>
            <Field label="Scope status"><Badge>{a.scopeStatus}</Badge></Field>
            <Field label="HTTP status">{a.httpStatus ?? "—"}</Field>
            <Field label="Target">{a.target ? `${a.target.value} (${a.target.type})` : "—"}</Field>
            <Field label="First seen">{a.firstSeen ? new Date(a.firstSeen).toLocaleString() : "—"}</Field>
            <Field label="Last seen">{a.lastSeen ? new Date(a.lastSeen).toLocaleString() : "—"}</Field>
            <Field label="Discovery sources">{(a.sources ?? []).join(", ") || "—"}</Field>
            <Field label="Discovered by scan">{a.discoveredByScanId ? <Link href={`/scans/${a.discoveredByScanId}`} className="text-sky-300 hover:underline">{a.discoveredByScanId.slice(0, 8)}…</Link> : "—"}</Field>
          </div>
        </Card>

        <Card title={`Services (${a.services?.length ?? 0})`}>
          {(a.services ?? []).length === 0 && <p className="text-sm text-slate-500">No services recorded.</p>}
          <div className="space-y-1">
            {(a.services ?? []).map((s) => (
              <p key={s.id} className="text-sm text-slate-200">
                {s.port}/{s.protocol} — {s.name ?? "unknown"}{s.product ? ` · ${s.product}` : ""}{s.version ? ` ${s.version}` : ""}
              </p>
            ))}
          </div>
        </Card>

        <Card title={`Technologies (${a.technologies?.length ?? 0})`}>
          {(a.technologies ?? []).length === 0 && <p className="text-sm text-slate-500">No technologies detected.</p>}
          <div className="space-y-1">
            {(a.technologies ?? []).map((t) => (
              <p key={t.id} className="text-sm text-slate-200">
                {t.name}{t.version ? ` ${t.version}` : ""} <span className="text-slate-500">· {t.category ?? "Other"}{t.source ? ` · via ${t.source}` : ""}{t.confidence != null ? ` · confidence ${Math.round(t.confidence * 100)}%` : ""}</span>
              </p>
            ))}
          </div>
        </Card>

        <Card title={`Endpoints (${a.endpoints?.length ?? 0})`}>
          {(a.endpoints ?? []).length === 0 && <p className="text-sm text-slate-500">No endpoints recorded.</p>}
          <div className="space-y-1">
            {(a.endpoints ?? []).map((e) => (
              <p key={e.id} className="break-all text-sm text-slate-200">
                <span className="text-slate-400">{e.method}</span> <Link href={`/endpoints/${e.id}`} className="text-sky-300 hover:underline">{e.url}</Link>
                <span className="text-slate-500"> · {e.statusCode ?? "—"}{e.source ? ` · ${e.source}` : ""}{(e.parameterNames ?? []).length ? ` · params: ${(e.parameterNames ?? []).join(", ")}` : ""}{e.scopeStatus ? ` · ${e.scopeStatus}` : ""}</span>
              </p>
            ))}
          </div>
        </Card>

        {risk && (
          <Card title="Vulnerability Risk (Prompt 11 §70)">
            <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
              <Field label="Open vulnerabilities">{risk.openCount}</Field>
              <Field label="Worst risk score">{risk.worstRiskScore}</Field>
              <Field label="KEV listed">{risk.kevCount}</Field>
              <Field label="Overdue SLA">{risk.overdueCount}</Field>
            </div>
            <div className="mt-3 space-y-1">
              {risk.findings.slice(0, 10).map((f) => (
                <p key={f.id} className="text-sm text-slate-200">
                  <Link href={`/vulnerabilities/${f.id}`} className="text-sky-300 hover:underline">{f.title}</Link>
                  <span className="text-slate-500"> · {f.severity} · {f.priority ?? "unprioritized"} · {f.lifecycleStatus}</span>
                </p>
              ))}
              {risk.findings.length === 0 && <p className="text-sm text-slate-500">No vulnerabilities recorded for this asset. Canonical findings only — duplicates are observations and are never double-counted.</p>}
            </div>
          </Card>
        )}

        {surface && surface.totalEndpoints > 0 && (
          <Card title="Web Surface (Prompt 6)">
            <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
              <Field label="Endpoints">{surface.totalEndpoints}</Field>
              <Field label="API endpoints">{surface.apiEndpoints}</Field>
              <Field label="Sensitive routes">{surface.sensitiveRoutes}</Field>
              <Field label="JavaScript resources">{surface.javascriptResources}</Field>
              <Field label="Parameters discovered">{surface.parametersDiscovered}</Field>
              <Field label="Endpoints with parameters">{surface.endpointsWithParameters}</Field>
              <Field label="Forms discovered">{surface.formsDiscovered}</Field>
              <Field label="By source">{surface.endpointsBySource ? Object.entries(surface.endpointsBySource).map(([k, v]) => `${k} (${v})`).join(", ") : "—"}</Field>
            </div>
            <p className="mt-3 text-xs text-slate-500">Discovery inventory only — route classifications are labels for prioritization, not findings.</p>
          </Card>
        )}
      </div>
    </>
  );
}
