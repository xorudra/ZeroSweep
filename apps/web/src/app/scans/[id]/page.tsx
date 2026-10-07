"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { api, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Live Scan page (Prompt 4 §42–§44). Polls the scan-details + durable-events
 * APIs (the SSE endpoint /scans/:id/stream serves the same event contract for
 * streaming clients). Raw process logs and secrets are never shown — only
 * server-generated lifecycle events, stage state and counters.
 */

interface StageRow {
  type: string;
  status: string;
  progress: number;
  dependencies?: string[];
  metadata?: { selectedAdapters?: { slug: string; simulation?: boolean }[] } | null;
  startedAt?: string | null;
  completedAt?: string | null;
}
interface ExecutionRow {
  id: string;
  status: string;
  toolId: string;
  tool?: { slug: string; name: string } | null;
  metrics?: Record<string, number> | null;
  exitCode?: number | null;
  error?: string | null;
  startedAt?: string | null;
  completedAt?: string | null;
}
interface ReconSummary {
  totalAssets: number;
  inScopeAssets: number;
  outOfScopeAssets: number;
  subdomains: number;
  resolvedHosts: number;
  httpServices: number;
  totalServices: number;
  technologies: number;
  totalEndpoints: number;
  historicalUrls: number;
  crawlUrls: number;
  outOfScopeEndpoints: number;
  bySource?: Record<string, number>;
  toolsRun?: { slug?: string; name?: string; status: string }[];
}
interface ScanFindingsSummary {
  totalFindings: number;
  uniqueFindings: number;
  duplicatesMerged: number;
  bySeverity: Record<string, number>;
  confirmed: number;
  likely: number;
  unverified: number;
  falsePositives: number;
  acceptedRisks: number;
  byTool: Record<string, { total: number; contributed: number }>;
}
interface WebSurfaceSummary {
  totalEndpoints: number;
  inScopeEndpoints: number;
  outOfScopeEndpoints: number;
  apiEndpoints: number;
  sensitiveRoutes: number;
  javascriptResources: number;
  parametersDiscovered: number;
  uniqueParameterNames: number;
  endpointsWithParameters: number;
  formsDiscovered: number;
  endpointsBySource?: Record<string, number>;
  endpointsByType?: Record<string, number>;
  endpointsByStatusClass?: Record<string, number>;
  contentDiscoveryToolsRun?: string[];
}
interface ScanDetails {
  id: string;
  status: string;
  progress: number;
  currentStage?: string | null;
  startedAt?: string | null;
  completedAt?: string | null;
  createdAt: string;
  stages?: StageRow[];
  executions?: ExecutionRow[];
  findingCounts?: Record<string, number>;
  assetCount?: number;
  workers?: { workerId: string; status: string; lastHeartbeat: string }[];
  assessment?: { name?: string; profile?: string; target?: { value?: string } };
}
interface ScanEvent { id: string; type: string; payload?: Record<string, unknown> | null; createdAt: string }

const TERMINAL = new Set(["COMPLETED", "PARTIAL", "FAILED", "CANCELLED"]);
const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"];

function stageTone(status: string): string {
  switch (status) {
    case "COMPLETED": return "bg-emerald-500/15 text-emerald-300";
    case "RUNNING": return "bg-sky-500/15 text-sky-300";
    case "FAILED": return "bg-red-500/15 text-red-300";
    case "PARTIAL": return "bg-amber-500/15 text-amber-300";
    case "CANCELLED": case "SKIPPED": return "bg-slate-500/15 text-slate-400";
    case "READY": case "QUEUED": return "bg-violet-500/15 text-violet-300";
    default: return "bg-slate-500/10 text-slate-500";
  }
}

function elapsed(scan: ScanDetails | null): string {
  if (!scan?.startedAt) return "—";
  const end = scan.completedAt ? new Date(scan.completedAt).getTime() : Date.now();
  const s = Math.max(0, Math.floor((end - new Date(scan.startedAt).getTime()) / 1000));
  return `${Math.floor(s / 60)}m ${s % 60}s`;
}

export default function Page() {
  const params = useParams<{ id: string }>();
  const id = params.id;
  const [scan, setScan] = useState<ScanDetails | null>(null);
  const [recon, setRecon] = useState<ReconSummary | null>(null);
  const [surface, setSurface] = useState<WebSurfaceSummary | null>(null);
  const [findingsSummary, setFindingsSummary] = useState<ScanFindingsSummary | null>(null);
  const [events, setEvents] = useState<ScanEvent[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [, setTick] = useState(0);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  const load = useCallback(async () => {
    try {
      const [details, ev] = await Promise.all([api.scanDetails(id), api.scanEvents(id)]);
      setScan(details as ScanDetails);
      setEvents((ev as { items: ScanEvent[] }).items ?? []);
      // Recon summary is best-effort: older scans may have no recon data.
      api.reconSummary(id).then((r) => setRecon(r as ReconSummary)).catch(() => undefined);
      // Web-surface summary is best-effort too (Prompt 6 §54).
      api.webSurface(id).then((r) => setSurface(r as WebSurfaceSummary)).catch(() => undefined);
      api.scanFindingsSummary(id).then((r) => setFindingsSummary(r as ScanFindingsSummary)).catch(() => undefined);
      setError(null);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not load scan");
    }
  }, [id]);

  useEffect(() => {
    void load();
    timer.current = setInterval(() => { setTick((t) => t + 1); void load(); }, 2000);
    return () => { if (timer.current) clearInterval(timer.current); };
  }, [load]);

  useEffect(() => {
    if (scan && TERMINAL.has(scan.status) && timer.current) {
      clearInterval(timer.current);
      timer.current = null;
    }
  }, [scan]);

  const act = async (action: "pause" | "resume" | "cancel" | "stop") => {
    setBusy(action);
    try {
      if (action === "pause") await api.pauseScan(id);
      if (action === "resume") await api.resumeScan(id);
      if (action === "cancel") await api.cancelScan(id);
      if (action === "stop") await api.stopScan(id);
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : `Could not ${action} scan`);
    } finally {
      setBusy(null);
    }
  };

  const simulation = (scan?.stages ?? []).some((s) => (s.metadata?.selectedAdapters ?? []).some((a) => a.simulation));

  return (
    <>
      <PageHeader
        eyebrow="Live Scan"
        title={scan?.assessment?.name ?? "Scan"}
        body={scan ? `${scan.assessment?.target?.value ?? ""} · ${scan.assessment?.profile ?? ""}` : "Loading scan…"}
      />
      {error && <Card><p className="text-sm text-red-300">{error}</p></Card>}
      {!scan && !error && <EmptyState title="Loading scan" body="Fetching live scan state…" />}
      {scan && (
        <div className="space-y-6">
          {simulation && (
            <Card>
              <p className="text-sm text-amber-300">
                Simulation / Development Mode — this pipeline is executed by the Mock adapter to validate
                orchestration. No real security tool has run and no target was contacted.
              </p>
            </Card>
          )}

          <Card>
            <div className="flex flex-wrap items-center gap-4">
              <Badge>{scan.status}</Badge>
              <div className="min-w-48 flex-1">
                <div className="h-2 rounded bg-slate-800">
                  <div className="h-2 rounded bg-sky-500 transition-all" style={{ width: `${scan.progress}%` }} />
                </div>
                <p className="mt-1 text-xs text-slate-400">{scan.progress}% · current stage: {scan.currentStage ?? "—"} · elapsed {elapsed(scan)}</p>
              </div>
              <div className="flex gap-2">
                {scan.status === "RUNNING" && (
                  <button disabled={busy !== null} onClick={() => void act("pause")} className="rounded bg-slate-800 px-3 py-1.5 text-sm text-slate-200 disabled:opacity-50">Pause</button>
                )}
                {scan.status === "PAUSED" && (
                  <button disabled={busy !== null} onClick={() => void act("resume")} className="rounded bg-sky-600 px-3 py-1.5 text-sm text-white disabled:opacity-50">Resume</button>
                )}
                {!TERMINAL.has(scan.status) && (
                  <>
                    <button disabled={busy !== null} onClick={() => void act("cancel")} className="rounded bg-slate-800 px-3 py-1.5 text-sm text-slate-200 disabled:opacity-50">Cancel</button>
                    <button disabled={busy !== null} onClick={() => void act("stop")} className="rounded bg-red-600 px-3 py-1.5 text-sm text-white disabled:opacity-50">Emergency stop</button>
                  </>
                )}
              </div>
            </div>
          </Card>

          <div className="grid grid-cols-2 gap-3 md:grid-cols-6">
            {SEVERITIES.map((sev) => (
              <Card key={sev}>
                <p className="text-xs uppercase tracking-wide text-slate-500">{sev}</p>
                <p className="mt-1 text-2xl text-slate-100">{scan.findingCounts?.[sev] ?? 0}</p>
              </Card>
            ))}
            <Card>
              <p className="text-xs uppercase tracking-wide text-slate-500">Assets</p>
              <p className="mt-1 text-2xl text-slate-100">{scan.assetCount ?? 0}</p>
            </Card>
          </div>

          <Card>
            <h3 className="text-sm font-semibold text-slate-200">Pipeline (DAG)</h3>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              {(scan.stages ?? []).map((stage, i) => (
                <span key={stage.type} className="flex items-center gap-2">
                  {i > 0 && <span className="text-slate-600">→</span>}
                  <span className={`rounded px-2 py-1 text-xs ${stageTone(stage.status)}`} title={`depends on: ${(stage.dependencies ?? []).join(", ") || "none"}`}>
                    {stage.type} · {stage.status}
                  </span>
                </span>
              ))}
            </div>
            <div className="mt-4 space-y-1">
              {(scan.executions ?? []).map((ex) => (
                <p key={ex.id} className="text-xs text-slate-400">
                  {ex.tool ? `${ex.tool.name} (${ex.tool.slug})` : `tool execution ${ex.id.slice(0, 8)}…`} — {ex.status}
                  {ex.metrics ? ` · assets ${ex.metrics.assets ?? 0} · services ${ex.metrics.services ?? 0} · endpoints ${ex.metrics.endpoints ?? 0}${ex.metrics.parameters ? ` · parameters ${ex.metrics.parameters}` : ""}` : ""}
                  {ex.error ? ` · ${ex.error}` : ""}
                  {ex.startedAt ? ` · started ${new Date(ex.startedAt).toLocaleTimeString()}` : ""}
                </p>
              ))}
              {(scan.workers ?? []).map((w) => (
                <p key={w.workerId} className="text-xs text-slate-500">
                  worker {w.workerId} — {w.status} · heartbeat {new Date(w.lastHeartbeat).toLocaleTimeString()}
                </p>
              ))}
            </div>
          </Card>

          {recon && recon.totalAssets + recon.totalEndpoints > 0 && (
            <Card>
              <h3 className="text-sm font-semibold text-slate-200">Recon Summary</h3>
              <p className="mt-1 text-xs text-slate-500">Inventory discovered by this scan — not vulnerability counts.</p>
              <div className="mt-3 grid grid-cols-2 gap-3 md:grid-cols-4">
                {[
                  ["Assets", recon.totalAssets],
                  ["In scope", recon.inScopeAssets],
                  ["Out of scope", recon.outOfScopeAssets],
                  ["Subdomains", recon.subdomains],
                  ["Resolved hosts", recon.resolvedHosts],
                  ["HTTP services", recon.httpServices],
                  ["Technologies", recon.technologies],
                  ["Endpoints", recon.totalEndpoints],
                  ["Historical URLs", recon.historicalUrls],
                  ["Crawl URLs", recon.crawlUrls],
                ].map(([label, value]) => (
                  <div key={label as string}>
                    <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
                    <p className="mt-1 text-xl text-slate-100">{value}</p>
                  </div>
                ))}
              </div>
              {recon.bySource && Object.keys(recon.bySource).length > 0 && (
                <p className="mt-3 text-xs text-slate-400">
                  Discovered by: {Object.entries(recon.bySource).map(([tool, n]) => `${tool} (${n})`).join(", ")}
                </p>
              )}
              {recon.toolsRun && recon.toolsRun.length > 0 && (
                <p className="mt-1 text-xs text-slate-500">
                  Tools run: {recon.toolsRun.map((t) => `${t.slug ?? t.name} — ${t.status}`).join(" · ")}
                </p>
              )}
            </Card>
          )}

          {surface && surface.totalEndpoints > 0 && (
            <Card>
              <h3 className="text-sm font-semibold text-slate-200">Web Surface</h3>
              <p className="mt-1 text-xs text-slate-500">Content, route and parameter discovery for this scan (Prompt 6) — inventory metrics, not vulnerability counts.</p>
              <div className="mt-3 grid grid-cols-2 gap-3 md:grid-cols-4">
                {[
                  ["Endpoints", surface.totalEndpoints],
                  ["In scope", surface.inScopeEndpoints],
                  ["Out of scope (recorded)", surface.outOfScopeEndpoints],
                  ["API endpoints", surface.apiEndpoints],
                  ["Sensitive routes", surface.sensitiveRoutes],
                  ["JavaScript resources", surface.javascriptResources],
                  ["Parameters", surface.parametersDiscovered],
                  ["Unique parameter names", surface.uniqueParameterNames],
                  ["Endpoints with parameters", surface.endpointsWithParameters],
                  ["Forms", surface.formsDiscovered],
                ].map(([label, value]) => (
                  <div key={label as string}>
                    <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
                    <p className="mt-1 text-xl text-slate-100">{value}</p>
                  </div>
                ))}
              </div>
              {surface.endpointsBySource && Object.keys(surface.endpointsBySource).length > 0 && (
                <p className="mt-3 text-xs text-slate-400">
                  By source: {Object.entries(surface.endpointsBySource).map(([tool, n]) => `${tool} (${n})`).join(", ")}
                </p>
              )}
              {surface.endpointsByType && Object.keys(surface.endpointsByType).length > 0 && (
                <p className="mt-1 text-xs text-slate-400">
                  By type: {Object.entries(surface.endpointsByType).map(([t, n]) => `${t} (${n})`).join(", ")}
                </p>
              )}
              {surface.contentDiscoveryToolsRun && surface.contentDiscoveryToolsRun.length > 0 && (
                <p className="mt-1 text-xs text-slate-500">
                  Discovery tools: {[...new Set(surface.contentDiscoveryToolsRun)].join(", ")}
                </p>
              )}
            </Card>
          )}

          {findingsSummary && findingsSummary.uniqueFindings > 0 && (
            <Card>
              <h3 className="text-sm font-semibold text-slate-200">Findings</h3>
              <p className="mt-1 text-xs text-slate-500">Safe vulnerability detection + TLS assessment for this scan (Prompt 7) — canonical findings after correlation; duplicates merged, never deleted.</p>
              <div className="mt-3 grid grid-cols-2 gap-3 md:grid-cols-4">
                {[
                  ["Unique findings", findingsSummary.uniqueFindings],
                  ["Duplicates merged", findingsSummary.duplicatesMerged],
                  ["Critical", findingsSummary.bySeverity.CRITICAL ?? 0],
                  ["High", findingsSummary.bySeverity.HIGH ?? 0],
                  ["Medium", findingsSummary.bySeverity.MEDIUM ?? 0],
                  ["Low", findingsSummary.bySeverity.LOW ?? 0],
                  ["Likely (corroborated)", findingsSummary.likely],
                  ["Unverified", findingsSummary.unverified],
                  ["False positives", findingsSummary.falsePositives],
                  ["Accepted risks", findingsSummary.acceptedRisks],
                ].map(([label, value]) => (
                  <div key={label as string}>
                    <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
                    <p className="mt-1 text-xl text-slate-100">{value}</p>
                  </div>
                ))}
              </div>
              {findingsSummary.byTool && Object.keys(findingsSummary.byTool).length > 0 && (
                <p className="mt-3 text-xs text-slate-400">
                  Tool contribution: {Object.entries(findingsSummary.byTool).map(([tool, s]) => `${tool} (${s.contributed} canonical of ${s.total} reports)`).join(", ")}
                </p>
              )}
              <p className="mt-2 text-xs"><Link href={`/findings?scanId=${id}`} className="text-sky-300 hover:underline">Open this scan&rsquo;s findings →</Link></p>
            </Card>
          )}

          <Card>
            <h3 className="text-sm font-semibold text-slate-200">Timeline</h3>
            {events.length === 0 && <p className="mt-2 text-sm text-slate-500">No events yet.</p>}
            <ul className="mt-3 space-y-2">
              {events.map((event) => (
                <li key={event.id} className="flex gap-3 text-sm">
                  <span className="shrink-0 text-xs text-slate-500">{new Date(event.createdAt).toLocaleTimeString()}</span>
                  <span className="text-slate-300">{event.type}</span>
                  {event.payload && Object.keys(event.payload).length > 0 && (
                    <span className="text-xs text-slate-500">{JSON.stringify(event.payload)}</span>
                  )}
                </li>
              ))}
            </ul>
          </Card>
        </div>
      )}
    </>
  );
}
