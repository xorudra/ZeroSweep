"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@zerosweep/ui";

/**
 * Endpoint detail (Prompt 6 §52): the full discovered record for one route —
 * response classification metadata, provenance across every tool that saw
 * it, scope verdict, redirect behaviour, and the parameter/form inventory.
 * Parameters are NAMES with locations and provenance; sensitive values are
 * never stored anywhere in the platform, so there is nothing secret to show.
 */
interface ParameterRow {
  id: string;
  name: string;
  location: string;
  sources?: string[];
  confidence?: number | null;
}
interface FormRow {
  id: string;
  method: string;
  fieldNames?: string[];
  encodingType?: string | null;
  source?: string | null;
}
interface EndpointDetail {
  id: string;
  url: string;
  method: string;
  statusCode?: number | null;
  contentType?: string | null;
  contentLength?: number | null;
  title?: string | null;
  redirectLocation?: string | null;
  endpointType?: string;
  classification?: string | null;
  parameterNames?: string[];
  source?: string | null;
  sources?: string[];
  scopeStatus?: string;
  asset?: { id: string; host: string } | null;
  parameters?: ParameterRow[];
  forms?: FormRow[];
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
      <div className="mt-1 break-all text-sm text-slate-200">{children}</div>
    </div>
  );
}

export default function Page() {
  const params = useParams<{ id: string }>();
  const [state, setState] = useState<{ kind: "loading" } | { kind: "error"; message: string } | { kind: "ready"; endpoint: EndpointDetail }>({ kind: "loading" });

  useEffect(() => {
    let cancelled = false;
    apiFetch<EndpointDetail>(`/endpoints/${params.id}`)
      .then((endpoint) => { if (!cancelled) setState({ kind: "ready", endpoint }); })
      .catch((e: unknown) => { if (!cancelled) setState({ kind: "error", message: e instanceof ApiError ? e.message : "Could not reach the API." }); });
    return () => { cancelled = true; };
  }, [params.id]);

  if (state.kind === "loading") return <p className="text-sm text-slate-400">Loading…</p>;
  if (state.kind === "error") return <EmptyState title="Endpoint not found" body={state.message} />;
  const e = state.endpoint;
  return (
    <>
      <PageHeader eyebrow="Endpoint" title={`${e.method} ${e.url}`} body="Discovered route record. Classification labels support prioritization — they are not vulnerability findings." />
      <p className="mb-4 text-sm"><Link href="/endpoints" className="text-sky-300 hover:underline">← All endpoints</Link></p>
      <div className="space-y-6">
        <Card title="Overview">
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <Field label="Host">{e.asset ? <Link href={`/assets/${e.asset.id}`} className="text-sky-300 hover:underline">{e.asset.host}</Link> : "—"}</Field>
            <Field label="Type">{e.endpointType ?? "UNKNOWN"}</Field>
            <Field label="Classification">{e.classification ?? "—"}</Field>
            <Field label="Scope status"><Badge>{e.scopeStatus ?? "—"}</Badge></Field>
            <Field label="Status code">{e.statusCode ?? "—"}</Field>
            <Field label="Content type">{e.contentType ?? "—"}</Field>
            <Field label="Content length">{e.contentLength ?? "—"}</Field>
            <Field label="Page title">{e.title ?? "—"}</Field>
            <Field label="Redirect location">{e.redirectLocation ?? "—"}</Field>
            <Field label="Discovered by">{[...new Set([...(e.sources ?? []), ...(e.source ? [e.source] : [])])].join(", ") || "—"}</Field>
          </div>
        </Card>

        <Card title={`Parameters (${e.parameters?.length ?? 0})`}>
          {(e.parameters ?? []).length === 0 && <p className="text-sm text-slate-500">No parameters discovered for this endpoint.</p>}
          <div className="space-y-1">
            {(e.parameters ?? []).map((p) => (
              <p key={p.id} className="text-sm text-slate-200">
                {p.name} <span className="text-slate-500">· {p.location.toLowerCase()}{(p.sources ?? []).length ? ` · via ${[...new Set(p.sources ?? [])].join(", ")}` : ""}{p.confidence != null ? ` · confidence ${Math.round(p.confidence * 100)}%` : ""}</span>
              </p>
            ))}
          </div>
          {(e.parameterNames ?? []).length > 0 && (
            <p className="mt-3 text-xs text-slate-500">Also observed in URLs: {(e.parameterNames ?? []).join(", ")}</p>
          )}
        </Card>

        <Card title={`Forms (${e.forms?.length ?? 0})`}>
          {(e.forms ?? []).length === 0 && <p className="text-sm text-slate-500">No forms recorded for this endpoint.</p>}
          <div className="space-y-1">
            {(e.forms ?? []).map((f) => (
              <p key={f.id} className="text-sm text-slate-200">
                {f.method} form <span className="text-slate-500">· fields: {(f.fieldNames ?? []).join(", ") || "—"}{f.encodingType ? ` · ${f.encodingType}` : ""}{f.source ? ` · via ${f.source}` : ""}</span>
              </p>
            ))}
          </div>
        </Card>
      </div>
    </>
  );
}
