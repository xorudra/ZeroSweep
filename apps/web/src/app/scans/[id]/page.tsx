"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { useParams } from "next/navigation";
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
  startedAt?: string | null;
  completedAt?: string | null;
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
                  tool execution {ex.id.slice(0, 8)}… — {ex.status}
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
