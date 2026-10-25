"use client";

import { Card } from "@zerosweep/ui";
import { DashboardShell, Stat, useAnalytics } from "../DashboardShared";

interface AssetRisk {
  riskiestAssets: { asset: string; findings: number; worstSeverity: string; score: number }[];
  byEnvironment: Record<string, number>;
  byDomain: Record<string, number>;
}

/** Asset & technology risk dashboard (Prompt 20 §74). */
export default function AssetRiskDashboardPage() {
  const { data, error } = useAnalytics<AssetRisk>("/analytics/assets");
  return (
    <DashboardShell title="Asset Risk" subtitle="Where risk concentrates: assets, environments and domains.">
      {error ? <Card><p className="text-sm text-red-400">{error}</p></Card> : null}
      {!data ? <Card><p className="text-sm text-slate-400">Loading…</p></Card> : (
        <>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-2">
            <Stat label="Environments with findings" value={Object.keys(data.byEnvironment).length} />
            <Stat label="Domains with findings" value={Object.keys(data.byDomain).length} />
          </div>
          <Card>
            <h3 className="mb-2 text-sm font-semibold text-slate-200">Riskiest assets</h3>
            {data.riskiestAssets.length === 0 ? (
              <p className="text-xs text-slate-500">No data in scope — no findings recorded yet.</p>
            ) : (
              <ul className="space-y-1">
                {data.riskiestAssets.map((a) => (
                  <li key={a.asset} className="flex items-center justify-between text-sm">
                    <span className="text-slate-300">{a.asset}</span>
                    <span className="text-slate-400">{a.findings} open · worst {a.worstSeverity} · score {a.score}</span>
                  </li>
                ))}
              </ul>
            )}
          </Card>
        </>
      )}
    </DashboardShell>
  );
}
