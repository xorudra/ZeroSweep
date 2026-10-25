"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { Badge, Card, EmptyState } from "@zerosweep/ui";
import { apiFetch, ApiError } from "@/lib/api-client";

interface PatchItem {
  findingId: string; cveId: string; title: string; patchStatus: string;
  fixedVersion: string | null; conflictingFixedVersions: Record<string, { source: string; fixedVersion: string }[]> | null;
  advisories: { source: string; advisoryId: string | null; fixedVersion: string | null; mitigation: string | null }[];
  kevListed: boolean; epss: number | null;
}
interface PatchDashboard { byStatus: Record<string, number>; items: PatchItem[] }

/**
 * Patch intelligence console (Prompt 30 §101). A fix is presented only
 * when a reliable advisory source states it and no trusted source
 * disagrees — disagreements are shown, never silently resolved (§86).
 */
export default function Page() {
  const [data, setData] = useState<PatchDashboard | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    apiFetch<PatchDashboard>("/vulnerability-intelligence/patches").then(setData).catch((e: unknown) => setError(e instanceof ApiError ? e.message : "Could not load patch intelligence."));
  }, []);
  if (error) return <EmptyState title="Patch console unavailable" body={error} />;
  if (!data) return <p className="text-sm text-slate-400">Loading…</p>;
  return (
    <>
      <PageHeader eyebrow="Vulnerability Intelligence" title="Patch Intelligence" body="Fix availability for this workspace's open findings, exactly as advisory sources state it. No fix is ever invented — 'no known fix' requires sources that examined the CVE and offered none." />
      <div className="flex flex-wrap gap-2">
        {Object.entries(data.byStatus).map(([status, count]) => <Badge key={status}>{status}: {count}</Badge>)}
      </div>
      <Card>
        <h3 className="text-sm font-semibold text-slate-200">Findings by patch state</h3>
        {data.items.length === 0 ? <p className="mt-1 text-sm text-slate-500">No findings with assessed patch intelligence yet.</p> : (
          <ul className="mt-2 space-y-2 text-sm text-slate-300">
            {data.items.map((i) => (
              <li key={i.findingId}>
                <Link className="text-sky-300 hover:underline" href={`/vulnerabilities/cve/${i.cveId}`}>{i.cveId}</Link>
                {" "}<Badge>{i.patchStatus}</Badge>{i.kevListed ? <Badge tone="CRITICAL">KEV</Badge> : null}
                {" · "}{i.title}
                {i.fixedVersion ? <><br /><span className="text-slate-400">Fixed version: {i.fixedVersion}</span></> : null}
                {i.conflictingFixedVersions ? <><br /><span className="text-amber-300">Sources disagree on the fixed version — no single version is presented as definitive (§86).</span></> : null}
                {i.advisories.map((a, j) => <span key={j} className="block text-xs text-slate-500">{a.source}{a.advisoryId ? ` · ${a.advisoryId}` : ""}{a.mitigation ? ` · mitigation: ${a.mitigation}` : ""}</span>)}
              </li>
            ))}
          </ul>
        )}
      </Card>
    </>
  );
}
