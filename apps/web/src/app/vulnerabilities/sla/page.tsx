"use client";

import { useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { Card } from "@dsrclone/ui";
import { apiFetch } from "@/lib/api-client";

interface SlaDashboard {
  counts: Record<string, number>;
  exceptionsActive: number;
  meanTimeToVerifiedClosureHours: number | null;
  verificationBacklog: number;
}
interface Metrics {
  openFindings: number; slaCompliancePct: number | null;
  meanTimeToTriageHours: number | null; meanTimeToFixClaimHours: number | null;
  meanTimeToVerifiedClosureHours: number | null;
  aging: Record<string, number>;
}

/**
 * SLA dashboard (Prompt 37 §114). Status is derived from stored due
 * dates, active exceptions and verification state — never estimated.
 * The three remediation clocks stay separate (§117): time to fix
 * CLAIM is not time to verified closure.
 */
export default function VulnerabilitySlaPage() {
  const [dash, setDash] = useState<SlaDashboard | null>(null);
  const [metrics, setMetrics] = useState<Metrics | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiFetch<SlaDashboard>("/vulnerability-management/sla-dashboard").then(setDash).catch((e: Error) => setError(e.message));
    apiFetch<Metrics>("/vulnerability-management/metrics").then(setMetrics).catch(() => undefined);
  }, []);

  const hours = (v: number | null | undefined) => (v == null ? "—" : `${Math.round(v)}h`);
  return (
    <div>
      <PageHeader eyebrow="Vulnerability Management" title="Vulnerability SLA" body="Derived from stored due dates, exceptions and verification state" />
      {error && <p role="alert">{error}</p>}
      {dash && (
        <div style={{ display: "grid", gap: 12, gridTemplateColumns: "repeat(auto-fit,minmax(170px,1fr))" }}>
          {Object.entries(dash.counts).map(([k, v]) => (
            <Card key={k}><h3>{k.replace(/_/g, " ")}</h3><p style={{ fontSize: 26 }}>{v}</p></Card>
          ))}
          <Card><h3>Active exceptions</h3><p style={{ fontSize: 26 }}>{dash.exceptionsActive}</p></Card>
          <Card><h3>Verification backlog</h3><p style={{ fontSize: 26 }}>{dash.verificationBacklog}</p></Card>
        </div>
      )}
      {metrics && (
        <Card>
          <h3>Remediation clocks (kept separate, §117)</h3>
          <p>Mean time to triage: {hours(metrics.meanTimeToTriageHours)}</p>
          <p>Mean time to fix claim: {hours(metrics.meanTimeToFixClaimHours)}</p>
          <p>Mean time to verified closure: {hours(metrics.meanTimeToVerifiedClosureHours)}</p>
          <p>Open: {metrics.openFindings} · Overdue: {dash?.counts.OVERDUE ?? "—"} · SLA compliance: {metrics.slaCompliancePct == null ? "— (no SLA-bound findings)" : `${metrics.slaCompliancePct}%`}</p>
          <h4>Aging of open findings (days)</h4>
          <ul>{Object.entries(metrics.aging).map(([bucket, count]) => <li key={bucket}>{bucket}: {count}</li>)}</ul>
        </Card>
      )}
    </div>
  );
}
