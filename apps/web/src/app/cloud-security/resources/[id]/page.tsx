"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card } from "@dsrclone/ui";

/**
 * Cloud resource detail (Prompt 14 §80). The full configuration
 * metadata view is a raw-artifact surface: the API gates it to
 * OWNER/ADMIN and audits every access (§103). Tags were sanitized at
 * ingestion — provider-controlled text can never inject markup here,
 * and any secret-shaped material was redacted before storage (§100).
 */
interface ResourceDetail {
  id: string; provider: string; resourceType: string; providerResourceId: string;
  name: string; region?: string | null; exposure: string; status: string; scopeStatus: string;
  tags: Record<string, string>; configurationMetadata: Record<string, unknown>;
  findings: Array<{ id: string; title: string; severity: string; ruleId?: string | null; findingClass?: string | null; status: string }>;
}

export default function Page() {
  const params = useParams<{ id: string }>();
  const [resource, setResource] = useState<ResourceDetail | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    void (async () => {
      try {
        setResource(await apiFetch<ResourceDetail>(`/cloud/resources/${params.id}`));
      } catch (e) {
        setError(e instanceof ApiError ? e.message : "Could not reach the API — resource detail requires the VIEW_CLOUD_ARTIFACTS permission (OWNER/ADMIN).");
      }
    })();
  }, [params.id]);

  if (!resource && !error) return <div className="p-6 text-sm text-slate-400">Loading…</div>;

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Cloud Resource" title={resource?.name ?? "Resource"} body="Configuration metadata as normalized by the inventory connectors — bounded security facts only. This view is access-audited." />
      {error && <p className="rounded bg-red-950/60 px-3 py-2 text-sm text-red-300">{error}</p>}
      {resource && (
        <>
          <Card>
            <div className="flex flex-wrap items-center gap-3 text-sm">
              <Badge>{resource.provider}</Badge>
              <span className="font-mono text-slate-300">{resource.resourceType}</span>
              <span className="text-slate-400">{resource.region ?? "global"}</span>
              <Badge>{resource.exposure}</Badge>
              <Badge>{resource.status}</Badge>
              {resource.scopeStatus !== "IN_SCOPE" && <Badge>{resource.scopeStatus}</Badge>}
            </div>
            <p className="mt-2 break-all font-mono text-xs text-slate-500">{resource.providerResourceId}</p>
          </Card>
          <Card>
            <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Tags (sanitized)</h2>
            {Object.keys(resource.tags ?? {}).length === 0 && <p className="text-sm text-slate-500">No tags.</p>}
            <div className="space-y-1 text-sm">
              {Object.entries(resource.tags ?? {}).map(([k, v]) => (
                <p key={k}><span className="font-mono text-slate-400">{k}</span>: <span className="text-slate-200">{v}</span></p>
              ))}
            </div>
          </Card>
          <Card>
            <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Configuration metadata</h2>
            <pre className="overflow-x-auto rounded bg-slate-900 p-3 text-xs text-slate-300">{JSON.stringify(resource.configurationMetadata ?? {}, null, 2)}</pre>
          </Card>
          <Card>
            <h2 className="mb-3 text-sm font-semibold uppercase tracking-wide text-slate-400">Findings on this resource</h2>
            {resource.findings.length === 0 && <p className="text-sm text-slate-500">No findings — passing controls are recorded as compliance evidence, not findings.</p>}
            <div className="divide-y divide-slate-800">
              {resource.findings.map((f) => (
                <div key={f.id} className="flex flex-wrap items-center gap-3 py-2 text-sm">
                  <Badge>{f.severity}</Badge>
                  <span className="text-slate-200">{f.title}</span>
                  <span className="font-mono text-xs text-slate-500">{f.ruleId ?? ""}</span>
                  <span className="ml-auto text-slate-500">{f.status}</span>
                </div>
              ))}
            </div>
          </Card>
        </>
      )}
    </div>
  );
}
