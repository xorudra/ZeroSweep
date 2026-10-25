"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Card, EmptyState, StatCard } from "@zerosweep/ui";

/** DevSecOps analytics (Prompt 27 §91) — repositories, pipeline gates, SAST/SCA trends, secret findings. */
interface KeyCount { key: string | null; count: number }
interface DevSecOps {
  sources: string[]; repositories: number;
  findingsByRepository: KeyCount[]; newFindingsByRepository: KeyCount[];
  secretFindings: number; newSecretFindings: number;
  pipelineGates: { total: number; passed: number; failed: number; passRate: number | null };
  scanCoverage: { scans: number; completed: number };
}

export default function Page() {
  const [data, setData] = useState<DevSecOps | null>(null);
  const [error, setError] = useState("");
  const load = useCallback(async () => {
    try { setData(await apiFetch<DevSecOps>("/analytics/devsecops")); }
    catch (e) { setError(e instanceof ApiError ? e.message : "Could not reach the API."); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="DevSecOps Analytics" title="DevSecOps" body="Repository security posture, quality-gate performance and secret-finding flow from pipeline and scan records." />
      {error && <p className="rounded bg-red-950/60 px-3 py-2 text-sm text-red-300">{error}</p>}
      {!data ? <EmptyState title="Loading DevSecOps analytics…" body="" /> : (
        <>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <StatCard label="Repositories" value={data.repositories} />
            <StatCard label="Gate pass rate" value={data.pipelineGates.passRate === null ? "—" : `${(data.pipelineGates.passRate * 100).toFixed(1)}%`} hint={`${data.pipelineGates.passed}/${data.pipelineGates.total} gates`} />
            <StatCard label="Secret findings" value={data.secretFindings} hint={`${data.newSecretFindings} new in range`} />
            <StatCard label="Scans completed" value={`${data.scanCoverage.completed}/${data.scanCoverage.scans}`} />
          </div>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <Card title="Findings by repository">
              {data.findingsByRepository.length === 0 ? <p className="text-sm text-slate-400">No repository-linked findings.</p> : (
                <ul className="space-y-1 text-sm">{data.findingsByRepository.map((r) => <li key={String(r.key)} className="flex justify-between"><span>{r.key}</span><span>{r.count}</span></li>)}</ul>
              )}
            </Card>
            <Card title="New findings by repository (range)">
              {data.newFindingsByRepository.length === 0 ? <p className="text-sm text-slate-400">No new repository findings in range.</p> : (
                <ul className="space-y-1 text-sm">{data.newFindingsByRepository.map((r) => <li key={String(r.key)} className="flex justify-between"><span>{r.key}</span><span>{r.count}</span></li>)}</ul>
              )}
            </Card>
          </div>
          <p className="text-xs text-slate-500">Sources: {data.sources.join(", ")}</p>
        </>
      )}
    </div>
  );
}
