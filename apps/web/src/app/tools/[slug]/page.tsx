"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";
import { TemplatePolicyPanel } from "@/components/TemplatePolicyPanel";
import { PROXY_SLUGS, ScannerConnectorPanel } from "@/components/ScannerConnectorPanel";

interface AdapterDetail {
  adapterVersion?: string;
  executionMode?: string;
  supportedTargets?: string[];
  capabilities?: string[];
  outputFormat?: string;
  parser?: string | null;
  defaultTimeout?: number;
  cpuLimit?: string;
  memoryLimit?: string;
  networkPolicy?: string;
  enabled?: boolean;
  inputSchema?: { requiresCredentials?: string[] } | null;
}
interface ToolDetail {
  slug: string;
  name: string;
  category: string;
  description?: string | null;
  version?: string | null;
  riskLevel: string;
  healthStatus: string;
  enabled: boolean;
  installed?: boolean;
  requiresApproval?: boolean;
  licenseType: string;
  adapters?: AdapterDetail[];
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div>
      <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
      <div className="mt-1 text-sm text-slate-200">{children}</div>
    </div>
  );
}

/** Adapter detail (Prompt 3 §44). Configuration VALUES and secrets are never
 *  shown — credential requirements appear as reference names only. */
interface LiveHealth { slug: string; healthStatus: string; installed: boolean; detail?: string; source?: string }

export default function Page() {
  const params = useParams<{ slug: string }>();
  const [state, setState] = useState<{ kind: "loading" } | { kind: "error"; message: string } | { kind: "ready"; tool: ToolDetail }>({ kind: "loading" });
  const [liveHealth, setLiveHealth] = useState<LiveHealth | null>(null);

  useEffect(() => {
    let cancelled = false;
    apiFetch<ToolDetail>(`/tools/${params.slug}`)
      .then((tool) => { if (!cancelled) setState({ kind: "ready", tool }); })
      .catch((e: unknown) => { if (!cancelled) setState({ kind: "error", message: e instanceof ApiError ? e.message : "Could not reach the API." }); });
    // Live adapter health (Prompt 5 §39): real version when the binary is
    // present on the API host, honest UNAVAILABLE when it is not.
    apiFetch<LiveHealth>(`/tools/${params.slug}/health`)
      .then((h) => { if (!cancelled && h.source) setLiveHealth(h); })
      .catch(() => undefined);
    return () => { cancelled = true; };
  }, [params.slug]);

  if (state.kind === "loading") return <p className="text-sm text-slate-400">Loading…</p>;
  if (state.kind === "error") return <EmptyState title="Tool not found" body={`${state.message} The tool may not be in the seeded catalog yet.`} />;

  const t = state.tool;
  const a = t.adapters?.[0];
  const credRefs = a?.inputSchema?.requiresCredentials ?? [];
  return (
    <>
      <PageHeader eyebrow={`Tool Registry / ${t.category}`} title={t.name} body={t.description ?? undefined} />
      <p className="mb-4 text-sm"><Link href="/tools" className="text-sky-300 hover:underline">← All tools</Link></p>
      <Card title="Adapter">
        <div className="grid grid-cols-2 gap-4 md:grid-cols-3">
          <Field label="Category">{t.category}</Field>
          <Field label="Tool version">{t.version ?? "Not pinned yet"}</Field>
          <Field label="Adapter version">{a?.adapterVersion ?? "—"}</Field>
          <Field label="Risk level"><Badge>{t.riskLevel}</Badge></Field>
          <Field label="Approval requirement">{t.requiresApproval ? "Explicit approval required" : "Standard policy gates apply"}</Field>
          <Field label="Execution mode">{a?.executionMode ?? "—"}</Field>
          <Field label="Health">
            {liveHealth ? (
              <>
                {liveHealth.healthStatus}
                {liveHealth.detail ? <span className="block text-xs text-slate-400">{liveHealth.detail}</span> : null}
                <span className="block text-xs text-slate-500">{liveHealth.source}</span>
              </>
            ) : t.healthStatus}
          </Field>
          <Field label="License model">{t.licenseType}{t.licenseType === "ADMIN_PROVIDED" ? " — supplied by the administrator; DSRclone does not redistribute it" : ""}</Field>
          <Field label="Configuration status">{a?.enabled ? "Adapter enabled" : "Catalog entry — adapter not yet implemented (metadata only)"}</Field>
          <Field label="Supported target types">{(a?.supportedTargets ?? []).join(", ") || "—"}</Field>
          <Field label="Capabilities">{(a?.capabilities ?? []).join(", ") || "—"}</Field>
          <Field label="Output / parser">{a ? `${a.outputFormat ?? "JSON"} / ${a.parser ?? "—"}` : "—"}</Field>
          <Field label="Default timeout">{a?.defaultTimeout ? `${a.defaultTimeout}s` : "—"}</Field>
          <Field label="Resource limits">{a ? `${a.cpuLimit ?? "—"} CPU · ${a.memoryLimit ?? "—"}` : "—"}</Field>
          <Field label="Network policy">{a?.networkPolicy ?? "—"}</Field>
          <Field label="Credential requirements">{credRefs.length ? credRefs.join(", ") + " (reference names only — values live in the vault)" : "None"}</Field>
        </div>
        <p className="mt-4 text-xs text-slate-500">Tools in DSRclone run only through authorized, scope-checked, approved assessment workflows in isolated workers. This page intentionally has no run or command control.</p>
      </Card>
      {t.slug === "nuclei" ? <TemplatePolicyPanel /> : null}
      {PROXY_SLUGS.includes(t.slug) ? <div className="mt-4"><ScannerConnectorPanel slug={t.slug} /></div> : null}
    </>
  );
}
