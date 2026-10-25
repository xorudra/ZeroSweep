"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Card, EmptyState, StatCard } from "@zerosweep/ui";

/** GRC analytics (Prompt 27 §94) — control failures, evidence freshness, assessment gaps. Assessment support only; never a certification claim. */
interface Grc {
  sources: string[]; controlFailures: number; controlsEvaluated: number;
  evidenceFreshness: { total: number; staleOrExpired: number; current: number };
  assessmentGaps: Array<{ key: string; version: string }>;
  highResidualRisks: number; expiringRiskAcceptances: number; openAuditFindings: number;
}

const DISCLAIMER = "ZeroSweep provides technical evidence, control monitoring, assessment support, risk tracking and audit preparation. It does not certify or attest compliance.";

export default function Page() {
  const [data, setData] = useState<Grc | null>(null);
  const [error, setError] = useState("");
  const load = useCallback(async () => {
    try { setData(await apiFetch<Grc>("/analytics/grc")); }
    catch (e) { setError(e instanceof ApiError ? e.message : "Could not reach the API."); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="GRC Analytics" title="GRC Analytics" body="Control evaluation outcomes, evidence freshness and assessment gaps derived from the GRC module's real records." />
      <p className="rounded bg-amber-950/60 px-3 py-2 text-sm text-amber-200">{DISCLAIMER}</p>
      {error && <p className="rounded bg-red-950/60 px-3 py-2 text-sm text-red-300">{error}</p>}
      {!data ? <EmptyState title="Loading GRC analytics…" body="" /> : (
        <>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <StatCard label="Controls evaluated" value={data.controlsEvaluated} />
            <StatCard label="Control failures" value={data.controlFailures} />
            <StatCard label="Stale / expired evidence" value={data.evidenceFreshness.staleOrExpired} hint={`${data.evidenceFreshness.current} current of ${data.evidenceFreshness.total}`} />
            <StatCard label="Open audit findings" value={data.openAuditFindings} />
          </div>
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            <Card title="Assessment gaps (frameworks with no assessment)">
              {data.assessmentGaps.length === 0 ? <p className="text-sm text-slate-400">Every registered framework has an assessment.</p> : (
                <ul className="space-y-1 text-sm">{data.assessmentGaps.map((g) => <li key={`${g.key}-${g.version}`}>{g.key} {g.version}</li>)}</ul>
              )}
            </Card>
            <Card title="Risk posture">
              <ul className="space-y-1 text-sm">
                <li className="flex justify-between"><span>High / critical residual risks</span><span>{data.highResidualRisks}</span></li>
                <li className="flex justify-between"><span>Risk acceptances expiring &lt; 30d</span><span>{data.expiringRiskAcceptances}</span></li>
              </ul>
            </Card>
          </div>
          <p className="text-xs text-slate-500">Sources: {data.sources.join(", ")}</p>
        </>
      )}
    </div>
  );
}
