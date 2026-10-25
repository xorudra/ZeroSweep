"use client";

import { Card } from "@zerosweep/ui";
import { CountTable, DashboardShell, Stat, useAnalytics } from "../DashboardShared";

interface SecurityOps {
  bySeverity: Record<string, number>;
  byStatus: Record<string, number>;
  bySourceDomain: Record<string, number>;
  byCategory: Record<string, number>;
  verificationCoverage: { verified: number; unverified: number; falsePositive: number };
  newInPeriod: number;
  resolvedInPeriod: number;
  retestPending: number;
  scanCoverage: string;
}

/** Security operations dashboard (Prompt 20 §72). */
export default function SecurityDashboardPage() {
  const { data, error } = useAnalytics<SecurityOps>("/analytics/security");
  return (
    <DashboardShell title="Security Operations" subtitle="Findings by severity, status, domain and verification — last 30 days.">
      {error ? <Card><p className="text-sm text-red-400">{error}</p></Card> : null}
      {!data ? <Card><p className="text-sm text-slate-400">Loading…</p></Card> : (
        <>
          <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
            <Stat label="New (30d)" value={data.newInPeriod} />
            <Stat label="Resolved (30d)" value={data.resolvedInPeriod} />
            <Stat label="Retest pending" value={data.retestPending} />
            <Stat label="Verified" value={data.verificationCoverage.verified} hint={`Unverified ${data.verificationCoverage.unverified} · False positive ${data.verificationCoverage.falsePositive}`} />
          </div>
          <div className="grid gap-4 md:grid-cols-2">
            <CountTable title="By severity" rows={data.bySeverity} />
            <CountTable title="By status" rows={data.byStatus} />
            <CountTable title="By source domain" rows={data.bySourceDomain} />
            <CountTable title="By category" rows={data.byCategory} />
          </div>
          <Card><p className="text-xs text-slate-500">Scan coverage: {data.scanCoverage}. Unknown coverage is never displayed as 100%.</p></Card>
        </>
      )}
    </DashboardShell>
  );
}
