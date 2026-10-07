"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState, StatCard } from "@dsrclone/ui";

/**
 * Per-API assessment view (Prompt 9 §55): one API service — its base
 * URL, declared authentication, linked specification and operation
 * inventory. Findings for the service live in Findings, filtered by
 * host; this view stays inventory + posture.
 */
interface Detail {
  service: {
    id: string; baseUrl: string; host: string; apiType: string;
    version?: string | null; authenticationType?: string | null;
    specificationId?: string | null; source: string; scopeStatus: string;
  };
  endpoints: Array<{
    id: string; url: string; method: string; operationId?: string | null;
    authRequired?: boolean | null; scopeStatus?: string;
  }>;
}

export default function Page() {
  const params = useParams<{ id: string }>();
  const [state, setState] = useState<{ kind: "loading" } | { kind: "error"; message: string } | { kind: "ready"; data: Detail }>({ kind: "loading" });

  useEffect(() => {
    let cancelled = false;
    apiFetch<Detail>(`/api-security/services/${params.id}`)
      .then((data) => { if (!cancelled) setState({ kind: "ready", data }); })
      .catch((e: unknown) => { if (!cancelled) setState({ kind: "error", message: e instanceof ApiError ? e.message : "Could not reach the API." }); });
    return () => { cancelled = true; };
  }, [params.id]);

  const s = state.kind === "ready" ? state.data.service : null;

  return (
    <>
      <PageHeader
        eyebrow="API Security · Service"
        title={s ? s.baseUrl : "API Service"}
        body="One API's inventory and declared posture. Operations marked state-changing or destructive in the source specification are excluded from automation by policy — they are listed here as inventory only."
      />
      {state.kind === "loading" && <p className="text-sm text-slate-400">Loading…</p>}
      {state.kind === "error" && <EmptyState title="Service not found" body={state.message} />}
      {state.kind === "ready" && s && (
        <div className="space-y-6">
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <StatCard label="Operations" value={state.data.endpoints.length} />
            <StatCard label="Auth required" value={state.data.endpoints.filter((e) => e.authRequired).length} />
            <StatCard label="Authentication" value={s.authenticationType ?? "unknown"} />
            <StatCard label="Scope" value={s.scopeStatus} />
          </div>
          <Card title="Service">
            <div className="space-y-1 text-sm text-slate-200">
              <p className="break-all">{s.baseUrl}</p>
              <p className="text-slate-500">
                {s.apiType} · version {s.version ?? "—"} · host {s.host} · via {s.source}
                {s.specificationId ? " · linked specification" : ""}
              </p>
              <p><Badge>{s.scopeStatus}</Badge></p>
            </div>
          </Card>
          <Card title="Operations">
            <div className="space-y-1">
              {state.data.endpoints.map((e) => (
                <p key={e.id} className="break-all text-sm text-slate-200">
                  <span className="text-slate-400">{e.method}</span>{" "}
                  <Link href={`/api-security/endpoints/${e.id}`} className="text-sky-300 hover:underline">{e.url}</Link>
                  <span className="text-slate-500">
                    {e.operationId ? ` · ${e.operationId}` : ""}
                    {e.authRequired ? " · auth required" : ""}
                  </span>{" "}
                  <Badge>{e.scopeStatus ?? "—"}</Badge>
                </p>
              ))}
              {state.data.endpoints.length === 0 && <p className="text-sm text-slate-500">No operations recorded for this service yet.</p>}
            </div>
          </Card>
          <p className="text-sm text-slate-400">
            <Link href="/api-security" className="text-sky-300 hover:underline">← Back to API Security</Link>
          </p>
        </div>
      )}
    </>
  );
}
