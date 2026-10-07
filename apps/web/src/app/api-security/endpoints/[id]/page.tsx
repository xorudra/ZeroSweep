"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * API endpoint detail (Prompt 9 §56): the operation behind the route —
 * operationId, path template, declared authentication, content types,
 * parameter inventory (names only) and the request/response schema
 * STRUCTURE (property names + types, never example values, §36).
 */
interface SchemaRow {
  id: string; name: string; schemaType: string;
  requiredFields: string[]; properties: Record<string, string>;
}
interface Detail {
  endpoint: {
    id: string; url: string; method: string; operationId?: string | null;
    path?: string | null; contentTypes: string[]; authRequired?: boolean | null;
    authSchemes: string[]; scopeStatus?: string; source?: string | null;
    sources?: string[]; statusCode?: number | null;
    parameters: Array<{ id: string; name: string; location: string }>;
  };
  requestSchema?: SchemaRow | null;
  responseSchema?: SchemaRow | null;
}

function SchemaBlock({ title, schema }: { title: string; schema?: SchemaRow | null }) {
  if (!schema) return null;
  return (
    <Card title={`${title} — ${schema.name}`}>
      <div className="space-y-1">
        {Object.entries(schema.properties).map(([name, type]) => (
          <p key={name} className="text-sm text-slate-200">
            {name} <span className="text-slate-500">· {type}</span>
            {schema.requiredFields.includes(name) && <span className="text-slate-500"> · required</span>}
          </p>
        ))}
        {Object.keys(schema.properties).length === 0 && <p className="text-sm text-slate-500">No properties recorded.</p>}
      </div>
    </Card>
  );
}

export default function Page() {
  const params = useParams<{ id: string }>();
  const [state, setState] = useState<{ kind: "loading" } | { kind: "error"; message: string } | { kind: "ready"; data: Detail }>({ kind: "loading" });

  useEffect(() => {
    let cancelled = false;
    apiFetch<Detail>(`/api-security/endpoints/${params.id}`)
      .then((data) => { if (!cancelled) setState({ kind: "ready", data }); })
      .catch((e: unknown) => { if (!cancelled) setState({ kind: "error", message: e instanceof ApiError ? e.message : "Could not reach the API." }); });
    return () => { cancelled = true; };
  }, [params.id]);

  const e = state.kind === "ready" ? state.data.endpoint : null;

  return (
    <>
      <PageHeader
        eyebrow="API Security · Endpoint"
        title={e ? `${e.method} ${e.path ?? e.url}` : "API Endpoint"}
        body="Operation detail from the API inventory. Path templates keep their {parameter} placeholders — concrete object identifiers from real users are never stored here."
      />
      {state.kind === "loading" && <p className="text-sm text-slate-400">Loading…</p>}
      {state.kind === "error" && <EmptyState title="Endpoint not found" body={state.message} />}
      {state.kind === "ready" && e && (
        <div className="space-y-6">
          <Card title="Operation">
            <div className="space-y-1 text-sm text-slate-200">
              <p className="break-all">{e.url}</p>
              <p className="text-slate-500">
                operationId {e.operationId ?? "—"} · status {e.statusCode ?? "—"} · via {[...new Set(e.sources ?? (e.source ? [e.source] : []))].join(", ") || "—"}
              </p>
              <p className="text-slate-500">
                authentication {e.authRequired == null ? "unknown" : e.authRequired ? `required (${e.authSchemes.join(", ") || "declared"})` : "not required"}
                {" "}· content types {e.contentTypes.join(", ") || "—"}
              </p>
              <p><Badge>{e.scopeStatus ?? "—"}</Badge></p>
            </div>
          </Card>
          <Card title="Parameters (names only)">
            <div className="space-y-1">
              {e.parameters.map((p) => (
                <p key={p.id} className="text-sm text-slate-200">{p.name} <span className="text-slate-500">· {p.location}</span></p>
              ))}
              {e.parameters.length === 0 && <p className="text-sm text-slate-500">No parameters recorded.</p>}
            </div>
          </Card>
          <SchemaBlock title="Request schema" schema={state.data.requestSchema} />
          <SchemaBlock title="Response schema" schema={state.data.responseSchema} />
          <p className="text-sm text-slate-400">
            <Link href="/api-security" className="text-sky-300 hover:underline">← Back to API Security</Link>
          </p>
        </div>
      )}
    </>
  );
}
