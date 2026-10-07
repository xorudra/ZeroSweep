"use client";

import { useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState, StatCard } from "@dsrclone/ui";

/**
 * GraphQL services (Prompt 9 §57): schema inventory from imported
 * introspection results and connector exports. Introspection being
 * enabled is an OBSERVATION, never a finding by itself (§29), and
 * mutations are inventoried but NOT automatically tested (§28).
 */
interface GraphqlRow {
  id: string; endpointUrl: string; schemaAvailable: boolean;
  queries: number; mutations: number; subscriptions: number; types: number;
  authenticationRequired?: boolean | null; source: string; scopeStatus: string;
}

export default function Page() {
  const [state, setState] = useState<{ kind: "loading" } | { kind: "error"; message: string } | { kind: "ready"; items: GraphqlRow[] }>({ kind: "loading" });

  useEffect(() => {
    let cancelled = false;
    apiFetch<GraphqlRow[]>("/api-security/graphql")
      .then((items) => { if (!cancelled) setState({ kind: "ready", items: items ?? [] }); })
      .catch((e: unknown) => { if (!cancelled) setState({ kind: "error", message: e instanceof ApiError ? e.message : "Could not reach the API." }); });
    return () => { cancelled = true; };
  }, []);

  const totals = state.kind === "ready"
    ? {
        queries: state.items.reduce((n, g) => n + g.queries, 0),
        mutations: state.items.reduce((n, g) => n + g.mutations, 0),
        types: state.items.reduce((n, g) => n + g.types, 0),
      }
    : null;

  return (
    <>
      <PageHeader
        eyebrow="API Security · GraphQL"
        title="GraphQL Services"
        body="GraphQL endpoints and their schema inventory. Queries are counted; mutations and subscriptions are inventoried but never executed by automated checks in this phase."
      />
      {state.kind === "loading" && <p className="text-sm text-slate-400">Loading…</p>}
      {state.kind === "error" && <EmptyState title="Nothing to show yet" body={`${state.message} Import a GraphQL introspection result or run an API assessment to populate this view.`} />}
      {state.kind === "ready" && totals && (
        <div className="space-y-6">
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <StatCard label="GraphQL services" value={state.items.length} />
            <StatCard label="Queries" value={totals.queries} />
            <StatCard label="Mutations" value={totals.mutations} hint="Inventoried — not automatically tested" />
            <StatCard label="Schema types" value={totals.types} />
          </div>
          <Card title="Services">
            <div className="space-y-1">
              {state.items.map((g) => (
                <p key={g.id} className="break-all text-sm text-slate-200">
                  {g.endpointUrl}
                  <span className="text-slate-500">
                    {" "}· schema {g.schemaAvailable ? "available" : "not retrieved"}
                    {" "}· {g.queries} queries · {g.mutations} mutations · {g.subscriptions} subscriptions · {g.types} types
                    {g.authenticationRequired ? " · auth required" : ""}
                    {" "}· via {g.source}
                  </span>{" "}
                  <Badge>{g.scopeStatus}</Badge>
                </p>
              ))}
              {state.items.length === 0 && <p className="text-sm text-slate-500">No GraphQL services recorded yet.</p>}
            </div>
          </Card>
        </div>
      )}
    </>
  );
}
