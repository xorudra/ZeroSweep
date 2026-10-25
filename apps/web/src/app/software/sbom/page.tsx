"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { Badge, Card, EmptyState } from "@zerosweep/ui";
import { apiFetch, ApiError } from "@/lib/api-client";

interface SbomRow { id: string; format: string; specVersion: string; artifactRef: string | null; componentCount: number; createdAt: string; confirmedMatches: number; potentialMatches: number }
interface ComponentRow { id: string; name: string; version?: string; ecosystem: string; purl: string; scope: string; bindingLabel: string; confirmedVulnerabilities: number; potentialVulnerabilities: number; unknownVulnerabilities: number }
interface Explorer { sboms: SbomRow[]; components: ComponentRow[]; totals: { confirmed: number; potential: number; unknown: number } }

/**
 * SBOM explorer (Prompt 30 §95): workspace SBOMs and their components
 * with correlation state. Confirmed and potential matches are always
 * counted separately — heuristic matches never inflate "confirmed".
 */
export default function Page() {
  const [data, setData] = useState<Explorer | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const load = () => apiFetch<Explorer>("/vulnerability-intelligence/sbom").then(setData).catch((e: unknown) => setError(e instanceof ApiError ? e.message : "Could not load the SBOM explorer."));
  useEffect(() => { load(); }, []);
  const correlate = async () => {
    const res = await apiFetch<{ components: number; matchesCreated: number; confirmed: number; potential: number }>("/vulnerability-intelligence/sbom/correlate", { method: "POST", body: "{}" }).catch(() => null);
    setNotice(res ? `Correlation complete: ${res.components} components evaluated · ${res.confirmed} confirmed · ${res.potential} potential.` : "Correlation failed — check your role permissions.");
    load();
  };
  if (error) return <EmptyState title="SBOM explorer unavailable" body={error} />;
  if (!data) return <p className="text-sm text-slate-400">Loading…</p>;
  return (
    <>
      <PageHeader eyebrow="Software Supply Chain" title="SBOM Explorer" body="Software bills of materials from source snapshots and container images, correlated against governed vulnerability intelligence." />
      <div className="flex flex-wrap items-center gap-2">
        <Badge tone="CRITICAL">Confirmed matches: {data.totals.confirmed}</Badge>
        <Badge>Potential matches: {data.totals.potential}</Badge>
        <Badge>Unknown: {data.totals.unknown}</Badge>
        <button className="rounded bg-sky-600 px-3 py-1 text-sm text-white" onClick={correlate}>Run correlation</button>
        {notice ? <span className="text-sm text-slate-300">{notice}</span> : null}
      </div>
      <Card>
        <h3 className="text-sm font-semibold text-slate-200">SBOMs</h3>
        {data.sboms.length === 0 ? <p className="mt-1 text-sm text-slate-500">No SBOMs recorded for this workspace yet — SBOMs arrive from source-code and container scans.</p> : (
          <ul className="mt-2 space-y-1 text-sm text-slate-300">
            {data.sboms.map((s) => <li key={s.id}>{s.format} {s.specVersion} · {s.artifactRef ?? s.id} · {s.componentCount} components · {s.confirmedMatches} confirmed / {s.potentialMatches} potential · {s.createdAt.slice(0, 10)}</li>)}
          </ul>
        )}
      </Card>
      <Card>
        <h3 className="text-sm font-semibold text-slate-200">Components</h3>
        {data.components.length === 0 ? <p className="mt-1 text-sm text-slate-500">No components in this workspace's inventory.</p> : (
          <ul className="mt-2 space-y-1 text-sm text-slate-300">
            {data.components.map((c) => (
              <li key={c.id}>
                <Link className="text-sky-300 hover:underline" href={`/software/components/${c.id}`}>{c.name}{c.version ? `@${c.version}` : ""}</Link>
                {" · "}{c.ecosystem} · {c.scope} · from {c.bindingLabel}
                {c.confirmedVulnerabilities > 0 ? <> · <Badge tone="CRITICAL">{c.confirmedVulnerabilities} confirmed</Badge></> : null}
                {c.potentialVulnerabilities > 0 ? <> · <Badge>{c.potentialVulnerabilities} potential</Badge></> : null}
              </li>
            ))}
          </ul>
        )}
      </Card>
    </>
  );
}
