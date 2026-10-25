"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Card, EmptyState } from "@zerosweep/ui";

/**
 * Network scan detail (Prompt 33 §116): scope, profile, stages, tools,
 * hosts/ports/services, findings, coverage, errors, budget and
 * timeline. Coverage gaps render as limitations — a scan with gaps is
 * COMPLETED_WITH_GAPS, never silently complete (§123).
 */
interface ScanDetail {
  scan: { id: string; status: string; createdAt?: string } | null;
  plan: {
    id: string; profile: string; status: string; stages: string[]; tools: string[];
    budget: Record<string, number>; blockedItems: Array<{ item: string; reason: string }>;
    scriptsUsed: Array<{ id: string; category: string }>; estimatedWorkloadClass: string;
  } | null;
  coverage: {
    completion: string; authorizedHosts: number; discoveredHosts: number; scannedHosts: number;
    portCoverage: number | null; serviceCoverage: number | null; vulnScannerCoverage: number | null;
    limitations: string[];
  };
}

export default function Page() {
  const params = useParams<{ id: string }>();
  const [detail, setDetail] = useState<ScanDetail | null>(null);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try { setDetail(await apiFetch<ScanDetail>(`/vapt/network/scans/${params.id}`)); }
    catch (e) { setError(e instanceof ApiError ? e.message : "Could not reach the API."); }
  }, [params.id]);

  useEffect(() => { void load(); }, [load]);

  if (!detail) return <main><PageHeader eyebrow="Network VAPT V2 · Scan" title="Scan" /><p>{error || "Loading…"}</p></main>;
  const { plan, coverage } = detail;
  return (
    <main>
      <PageHeader eyebrow="Network VAPT V2 · Scan" title={detail.scan?.id ?? params.id} />
      {error ? <p role="alert">{error}</p> : null}
      {plan ? (
        <>
          <Card title="Scope + profile">
            <p>Profile {plan.profile} · plan status {plan.status} · workload {plan.estimatedWorkloadClass}</p>
            <p>Stages: {plan.stages.join(" → ")}</p>
            <p>Tools: {plan.tools.join(", ")}</p>
            <p>NSE scripts: {plan.scriptsUsed.map((s) => `${s.id} (${s.category})`).join(", ") || "—"}</p>
          </Card>
          <Card title="Budget (§17/§18)">
            <ul>
              {Object.entries(plan.budget).map(([k, v]) => <li key={k}>{k}: {String(v)}</li>)}
            </ul>
          </Card>
          <Card title="Blocked items + errors">
            {plan.blockedItems.length === 0 ? <EmptyState title="No blocked items." body="Governance refusals (Masscan gate, NSE categories, FULL_TCP) would appear here." /> : (
              <ul>{plan.blockedItems.map((b) => <li key={b.item}><strong>{b.item}</strong> — {b.reason}</li>)}</ul>
            )}
          </Card>
        </>
      ) : <EmptyState title="No V2 plan attached." body="This scan predates Network VAPT V2 or was blocked at preflight — no plan, no fabricated detail." />}

      <Card title="Coverage (§121–§123)">
        <p>Completion: <strong>{coverage.completion}</strong></p>
        <p>Authorized {coverage.authorizedHosts} · discovered {coverage.discoveredHosts} · scanned {coverage.scannedHosts}</p>
        <p>
          Port coverage {coverage.portCoverage ?? "unknown"}% · service coverage {coverage.serviceCoverage ?? "unknown"}% ·
          vulnerability-scanner coverage {coverage.vulnScannerCoverage ?? "n/a"}%
        </p>
        {coverage.limitations.length > 0 ? (
          <ul>{coverage.limitations.map((l) => <li key={l}>{l}</li>)}</ul>
        ) : <p>No limitations recorded.</p>}
      </Card>
      <p><Link href="/vapt/network">← Back to Network VAPT</Link></p>
    </main>
  );
}
