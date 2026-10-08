"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Dynamic session detail (Prompt 35 §119). A dynamic session exists
 * only inside the governed lab: authorized application + authorized
 * device + reviewed instrumentation modules (§71–§87). This view is
 * read-only — it shows the device, the approved modules, the
 * traffic captures, runtime evidence metadata and the cleanup
 * state. There is no control here that attaches to a process, runs
 * a script or opens a shell: those capabilities do not exist in
 * DSRclone (§75–§84/§164).
 */
interface DynamicSession {
  id: string; applicationId: string; buildId: string; deviceId?: string | null;
  profile: string; status: string; requestedActions: string[]; blockedReasons: string[];
  moduleIds: string[]; killSwitchChecked: boolean; cleanupState: string;
  startedAt?: string | null; endedAt?: string | null;
  trafficSessions: Array<{ id: string; proxyTool: string; status: string; requestCount: number }>;
}

export default function Page() {
  const params = useParams<{ id: string }>();
  const [data, setData] = useState<DynamicSession | null>(null);
  const [state, setState] = useState<"loading" | "error" | "ready">("loading");
  const [error, setError] = useState("");

  useEffect(() => {
    let live = true;
    (async () => {
      try {
        const d = await apiFetch<DynamicSession>(`/mobile/dynamic-sessions/${params.id}`);
        if (!live) return;
        setData(d);
        setState("ready");
      } catch (e) {
        if (!live) return;
        setError(e instanceof ApiError ? e.message : "Failed to load dynamic session");
        setState("error");
      }
    })();
    return () => { live = false; };
  }, [params.id]);

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Mobile Security" title="Dynamic Analysis Session" body="Governed lab session — authorized app, authorized device, reviewed instrumentation modules only. Runtime evidence is sanitized before storage (§85/§91)." />
      <Link href="/mobile-security" className="text-sm text-indigo-300 hover:underline">← Mobile Security</Link>

      {state === "loading" && <p className="text-sm text-slate-400">Loading session…</p>}
      {state === "error" && <EmptyState title="Session unavailable" body={error} />}
      {state === "ready" && data && (
        <>
          <Card>
            <div className="flex flex-wrap items-center gap-3">
              <h2 className="text-lg font-medium text-slate-100">Session {data.id.slice(0, 8)}…</h2>
              <Badge>{data.status}</Badge>
              <Badge>{data.profile}</Badge>
              {data.killSwitchChecked && <Badge>Kill-switch checked</Badge>}
            </div>
            <dl className="mt-4 grid grid-cols-1 gap-2 text-sm text-slate-300 sm:grid-cols-2">
              <div>Application: <span className="text-slate-100">{data.applicationId}</span></div>
              <div>Build (artifact): <span className="text-slate-100">{data.buildId}</span></div>
              <div>Device: <span className="text-slate-100">{data.deviceId ?? "—"}</span></div>
              <div>Cleanup state (§87): <span className="text-slate-100">{data.cleanupState}</span></div>
              <div>Started: <span className="text-slate-100">{data.startedAt ?? "—"}</span></div>
              <div>Ended: <span className="text-slate-100">{data.endedAt ?? "—"}</span></div>
            </dl>
          </Card>

          <Card>
            <h3 className="mb-2 font-medium text-slate-100">Approved instrumentation modules (§80/§81)</h3>
            {data.moduleIds.length === 0
              ? <p className="text-sm text-slate-400">No instrumentation modules were part of this session.</p>
              : <ul className="list-disc pl-5 text-sm text-slate-300">{data.moduleIds.map((m) => <li key={m}>{m}</li>)}</ul>}
            <p className="mt-2 text-xs text-slate-500">Only registry modules with review status APPROVED may run. Arbitrary Frida scripts and arbitrary Objection commands are rejected by construction (§79/§84).</p>
          </Card>

          <Card>
            <h3 className="mb-2 font-medium text-slate-100">Requested actions &amp; policy outcome</h3>
            {data.requestedActions.length === 0
              ? <p className="text-sm text-slate-400">No actions requested.</p>
              : <ul className="list-disc pl-5 text-sm text-slate-300">{data.requestedActions.map((a) => <li key={a}>{a}</li>)}</ul>}
            {data.blockedReasons.length > 0 && (
              <>
                <h4 className="mt-3 text-sm font-medium text-red-300">Blocked reasons</h4>
                <ul className="list-disc pl-5 text-sm text-red-200">{data.blockedReasons.map((r) => <li key={r}>{r}</li>)}</ul>
              </>
            )}
          </Card>

          <Card>
            <h3 className="mb-2 font-medium text-slate-100">Traffic capture (§88–§93)</h3>
            {data.trafficSessions.length === 0
              ? <p className="text-sm text-slate-400">No traffic capture is attached to this session. Capture is scoped to the authorized test app/device and redacted before persistence (§90/§91).</p>
              : <ul className="space-y-1 text-sm text-slate-300">
                  {data.trafficSessions.map((t) => (
                    <li key={t.id}>{t.proxyTool} · {t.status} · {t.requestCount} requests · <Link className="text-indigo-300 hover:underline" href="/mobile-security/traffic">view</Link></li>
                  ))}
                </ul>}
          </Card>

          <Card>
            <h3 className="mb-2 font-medium text-slate-100">Session timeline</h3>
            <ol className="list-decimal pl-5 text-sm text-slate-300">
              <li>Session requested under an approved profile</li>
              <li>Kill-switch + instrumentation policy evaluated</li>
              <li>Status: {data.status}</li>
              <li>Cleanup (§87): {data.cleanupState} — stop app, remove temporary test data, revoke temporary secrets, release device, clear proxy configuration</li>
            </ol>
          </Card>
        </>
      )}
    </div>
  );
}
