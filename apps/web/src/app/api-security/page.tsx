"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState, StatCard } from "@dsrclone/ui";

/**
 * API Security dashboard (Prompt 9 §54/§60): the API inventory at a
 * glance — services, operations, imported specifications, GraphQL and
 * WebSocket surface, JWT profiles, and findings produced by SAFE checks
 * (schema conformance, JWT inspection, governed Nuclei API templates).
 * Imports yield inventory, never vulnerabilities; state-changing and
 * destructive operations are policy-blocked from automation (§17).
 */
interface Summary {
  apiServices: number; graphqlServices: number; apiEndpoints: number;
  specifications: number; webSockets: number; jwtProfiles: number;
  findingsTotal: number; findingsByClass: Record<string, number>;
}
interface ServiceRow {
  id: string; baseUrl: string; host: string; apiType: string;
  version?: string | null; authenticationType?: string | null;
  source: string; scopeStatus: string;
}
interface GraphqlRow {
  id: string; endpointUrl: string; schemaAvailable: boolean;
  queries: number; mutations: number; subscriptions: number; types: number;
  authenticationRequired?: boolean | null; source: string; scopeStatus: string;
}
interface SpecRow {
  id: string; kind: string; version?: string | null; location?: string | null;
  operationCount?: number | null; parsedStatus: string; source: string; createdAt: string;
}
interface EndpointRow {
  id: string; url: string; method: string; operationId?: string | null;
  authRequired?: boolean | null; scopeStatus?: string; source?: string | null;
}

type State =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; summary: Summary; rest: ServiceRow[]; graphql: GraphqlRow[]; specs: SpecRow[]; endpoints: EndpointRow[] };

export default function Page() {
  const [state, setState] = useState<State>({ kind: "loading" });

  useEffect(() => {
    let cancelled = false;
    Promise.all([
      apiFetch<Summary>("/api-security/summary"),
      apiFetch<{ rest: ServiceRow[]; graphql: GraphqlRow[] }>("/api-security/services"),
      apiFetch<SpecRow[]>("/api-security/specifications"),
      apiFetch<{ items: EndpointRow[] }>("/api-security/endpoints?pageSize=100"),
    ])
      .then(([summary, services, specs, endpoints]) => {
        if (!cancelled) setState({ kind: "ready", summary, rest: services.rest ?? [], graphql: services.graphql ?? [], specs: specs ?? [], endpoints: endpoints.items ?? [] });
      })
      .catch((e: unknown) => { if (!cancelled) setState({ kind: "error", message: e instanceof ApiError ? e.message : "Could not reach the API." }); });
    return () => { cancelled = true; };
  }, []);

  return (
    <>
      <PageHeader
        eyebrow="API Security"
        title="API Security"
        body="Discovered and imported APIs — OpenAPI/Swagger documents, Postman and Insomnia collections, GraphQL schemas, observed traffic — assessed with safe checks only. State-changing and destructive operations are policy-blocked from automation, never executed."
      />
      {state.kind === "loading" && <p className="text-sm text-slate-400">Loading…</p>}
      {state.kind === "error" && <EmptyState title="Nothing to show yet" body={`${state.message} When APIs are discovered or specifications imported, they will appear here.`} />}
      {state.kind === "ready" && (
        <div className="space-y-6">
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <StatCard label="API services" value={state.summary.apiServices} />
            <StatCard label="API endpoints" value={state.summary.apiEndpoints} />
            <StatCard label="GraphQL services" value={state.summary.graphqlServices} />
            <StatCard label="Imported specifications" value={state.summary.specifications} />
            <StatCard label="WebSocket endpoints" value={state.summary.webSockets} />
            <StatCard label="JWT profiles" value={state.summary.jwtProfiles} hint="Fingerprints + redacted claims — tokens never stored" />
            <StatCard label="API findings" value={state.summary.findingsTotal} hint="From safe checks only" />
          </div>
          <div className="grid gap-3 md:grid-cols-2">
            <Card title="Findings by class">
              {Object.entries(state.summary.findingsByClass).map(([k, v]) => (
                <p key={k} className="text-sm text-slate-200">{k} <span className="text-slate-500">· {v}</span></p>
              ))}
              {Object.keys(state.summary.findingsByClass).length === 0 && <p className="text-sm text-slate-500">No API findings yet — imports alone never create findings.</p>}
            </Card>
            <Card title="Imported specifications">
              {state.specs.map((s) => (
                <p key={s.id} className="break-all text-sm text-slate-200">
                  {s.kind} <span className="text-slate-500">· {s.operationCount ?? 0} operations · {s.parsedStatus} · via {s.source}</span>{" "}
                  <Badge>{s.version ?? "—"}</Badge>
                </p>
              ))}
              {state.specs.length === 0 && <p className="text-sm text-slate-500">No specifications imported yet.</p>}
            </Card>
          </div>
          <Card title="REST / HTTP API services">
            <div className="space-y-1">
              {state.rest.map((s) => (
                <p key={s.id} className="break-all text-sm text-slate-200">
                  <Link href={`/api-security/services/${s.id}`} className="text-sky-300 hover:underline">{s.baseUrl}</Link>
                  <span className="text-slate-500"> · {s.apiType} · auth {s.authenticationType ?? "unknown"} · via {s.source}</span>{" "}
                  <Badge>{s.scopeStatus}</Badge>
                </p>
              ))}
              {state.rest.length === 0 && <p className="text-sm text-slate-500">No REST API services yet.</p>}
            </div>
          </Card>
          <Card title="API endpoints">
            <div className="space-y-1">
              {state.endpoints.map((e) => (
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
              {state.endpoints.length === 0 && <p className="text-sm text-slate-500">No API endpoints discovered yet.</p>}
            </div>
          </Card>
          <p className="text-sm text-slate-400">
            Deep views: <Link href="/api-security/graphql" className="text-sky-300 hover:underline">GraphQL services</Link>
            {" · "}<Link href="/api-security/jwt" className="text-sky-300 hover:underline">JWT profiles</Link>
          </p>
        </div>
      )}
    </>
  );
}
