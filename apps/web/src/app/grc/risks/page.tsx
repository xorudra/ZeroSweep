"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@zerosweep/ui";

/** Risk dashboard (Prompt 26 §79): register, matrix, high residual
 *  risks, overdue treatments, expiring acceptances. Residual risk is
 *  shown only when control effectiveness is known (§49). */
interface RiskRow {
  id: string; title: string; source: string; status: string;
  inherentScore: number; inherentBand: string;
  residualScore: number | null; residualBand: string | null; residualBasis: string;
  likelihood: number;
}
interface RiskDashboard {
  risks: RiskRow[];
  matrix: Record<string, number>;
  highResidualRisks: RiskRow[];
  overdueTreatments: Array<{ id: string; action: string; dueDate: string }>;
  expiringAcceptances: Array<{ id: string; riskId: string; expiresAt: string }>;
}

export default function Page() {
  const [data, setData] = useState<RiskDashboard | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      setData(await apiFetch<RiskDashboard>("/grc/dashboard/risks"));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="GRC · Risk" title="Risk Register" body="Inherent risk is assessed at identification; residual risk appears only when linked-control effectiveness is known — never invented. RiskEngine V3 stays authoritative for technical vulnerability scores." />
      {error && <p className="rounded bg-red-950/60 px-3 py-2 text-sm text-red-300">{error}</p>}
      {!data ? (
        <EmptyState title="Loading risk register…" body="" />
      ) : (
        <>
          <div className="grid gap-4 md:grid-cols-3">
            <Card>
              <p className="text-xs uppercase text-slate-400">High residual risks</p>
              <p className="mt-1 text-2xl font-semibold">{data.highResidualRisks.length}</p>
            </Card>
            <Card>
              <p className="text-xs uppercase text-slate-400">Overdue treatment actions</p>
              <p className="mt-1 text-2xl font-semibold">{data.overdueTreatments.length}</p>
            </Card>
            <Card>
              <p className="text-xs uppercase text-slate-400">Acceptances expiring ≤ 31 days</p>
              <p className="mt-1 text-2xl font-semibold">{data.expiringAcceptances.length}</p>
              <p className="text-sm text-slate-400">Expired acceptances return risks to review automatically.</p>
            </Card>
          </div>
          <Card>
            <h3 className="mb-3 font-medium">Register</h3>
            {data.risks.length === 0 ? (
              <EmptyState title="No risks recorded" body="Risks arrive from findings, control failures, audit findings, vendors or manual entry." />
            ) : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-slate-400">
                    <th className="py-1">Risk</th><th>Source</th><th>Inherent</th><th>Residual</th><th>Status</th>
                  </tr>
                </thead>
                <tbody>
                  {data.risks.map((r) => (
                    <tr key={r.id} className="border-t border-slate-800">
                      <td className="py-2 pr-2">{r.title}</td>
                      <td className="pr-2">{r.source}</td>
                      <td className="pr-2">{r.inherentScore} ({r.inherentBand})</td>
                      <td className="pr-2">{r.residualScore === null ? <span className="text-slate-400">not assessed</span> : `${r.residualScore} (${r.residualBand})`}</td>
                      <td className="pr-2"><Badge>{r.status}</Badge></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>
          <Card>
            <h3 className="mb-3 font-medium">Risk matrix (likelihood × max impact → count)</h3>
            {Object.keys(data.matrix).length === 0 ? (
              <EmptyState title="Matrix is empty" body="Cells populate as risks are assessed." />
            ) : (
              <ul className="flex flex-wrap gap-2 text-sm">
                {Object.entries(data.matrix).map(([cell, count]) => (
                  <li key={cell} className="rounded border border-slate-700 px-2 py-1">{cell}: {count}</li>
                ))}
              </ul>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
