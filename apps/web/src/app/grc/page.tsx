"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";

/**
 * Compliance dashboard (Prompt 26 §76/§82). The headline metric is
 * "Assessment Coverage / Control Status" — DSRclone provides evidence
 * and assessment support; it never certifies an organization.
 */
interface Coverage {
  requirementsTotal: number; requirementsAssessed: number; controlsTotal: number;
  controlsImplemented: number; controlsTested: number; automatedControls: number;
  evidenceCurrent: number; evidenceTotal: number; manualEvidencePending: number;
  assessmentCoverage: number;
}
interface Dashboard {
  frameworks: Array<{ id: string; key: string; name: string; version: string; status: string }>;
  overallAssessmentStatus: string;
  coverage: Coverage;
  coverageLabel: string;
  technicalControlFailures: number;
  staleEvidence: number;
  openExceptions: number;
  upcomingReviews: number;
  disclaimer: string;
}

export default function Page() {
  const [data, setData] = useState<Dashboard | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      setData(await apiFetch<Dashboard>("/grc/dashboard/compliance"));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="GRC" title="Compliance" body="Frameworks, control status, evidence freshness and assessment coverage — computed from live platform evidence. Assessment states are not certification claims." />
      <p className="rounded bg-amber-950/60 px-3 py-2 text-sm text-amber-200">{data?.disclaimer || "DSRclone provides technical evidence, control monitoring, assessment support, risk tracking and audit preparation. It does not certify or attest compliance."}</p>
      {error && <p className="rounded bg-red-950/60 px-3 py-2 text-sm text-red-300">{error}</p>}
      <nav className="flex flex-wrap gap-2 text-sm">
        <Link className="rounded border border-slate-700 px-3 py-1" href="/grc/controls">Controls</Link>
        <Link className="rounded border border-slate-700 px-3 py-1" href="/grc/risks">Risk Register</Link>
        <Link className="rounded border border-slate-700 px-3 py-1" href="/grc/audits">Audits</Link>
        <Link className="rounded border border-slate-700 px-3 py-1" href="/grc/evidence">Evidence</Link>
      </nav>
      {!data ? (
        <EmptyState title="Loading compliance posture…" body="" />
      ) : (
        <>
          <div className="grid gap-4 md:grid-cols-4">
            <Card>
              <p className="text-xs uppercase text-slate-400">{data.coverageLabel}</p>
              <p className="mt-1 text-2xl font-semibold">{Math.round(data.coverage.assessmentCoverage * 100)}%</p>
              <p className="text-sm text-slate-400">{data.coverage.requirementsAssessed}/{data.coverage.requirementsTotal} requirements assessed · status {data.overallAssessmentStatus}</p>
            </Card>
            <Card>
              <p className="text-xs uppercase text-slate-400">Technical control failures</p>
              <p className="mt-1 text-2xl font-semibold">{data.technicalControlFailures}</p>
              <p className="text-sm text-slate-400">{data.coverage.controlsTested}/{data.coverage.controlsTotal} controls tested · {data.coverage.automatedControls} automated</p>
            </Card>
            <Card>
              <p className="text-xs uppercase text-slate-400">Stale / expired evidence</p>
              <p className="mt-1 text-2xl font-semibold">{data.staleEvidence}</p>
              <p className="text-sm text-slate-400">{data.coverage.evidenceCurrent}/{data.coverage.evidenceTotal} evidence current · {data.coverage.manualEvidencePending} manual pending review</p>
            </Card>
            <Card>
              <p className="text-xs uppercase text-slate-400">Exceptions & reviews</p>
              <p className="mt-1 text-2xl font-semibold">{data.openExceptions}</p>
              <p className="text-sm text-slate-400">open exceptions · {data.upcomingReviews} risk reviews due within 31 days</p>
            </Card>
          </div>
          <Card>
            <h3 className="mb-3 font-medium">Frameworks</h3>
            {data.frameworks.length === 0 ? (
              <EmptyState title="No frameworks imported" body="Import a framework version from the API (POST /api/v1/grc/frameworks/import-catalog/:key) to begin." />
            ) : (
              <ul className="divide-y divide-slate-800">
                {data.frameworks.map((f) => (
                  <li key={f.id} className="flex items-center justify-between py-2">
                    <Link className="hover:underline" href={`/grc/frameworks/${f.id}`}>{f.name} <span className="text-slate-400">{f.version}</span></Link>
                    <Badge>{f.status}</Badge>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
