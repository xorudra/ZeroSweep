"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Card, EmptyState } from "@dsrclone/ui";

/**
 * V2 scan detail (Prompt 32 §155): plan + stages, tool executions,
 * endpoints tested, skipped tests with reasons, coverage, evidence
 * count and cancel. Coverage is shown as measured — a null ratio
 * means "not measured", never 100% (§147/§148).
 */
interface ScanDetail {
  scan: { id: string; status: string; progress: number; startedAt?: string | null; completedAt?: string | null } | null;
  plan: {
    id: string; profileKey: string; status: string; stages: string[]; allowedTools: string[];
    blockedModules: Array<{ slug: string; reason: string }>; estimatedRequestClass: string;
    budget: Record<string, number>; scopeSnapshotId: string;
  } | null;
  coverage: {
    endpointCoverage: number | null; parameterCoverage: number | null; authenticatedCoverage: number | null;
    discoveredEndpoints: number; testedEndpoints: number;
    skipped: Array<{ test: string; reason: string }>; limitations: string[]; persisted?: boolean;
  };
  evidenceCount: number;
}

export default function Page() {
  const params = useParams<{ id: string }>();
  const id = params.id;
  const [detail, setDetail] = useState<ScanDetail | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setDetail(await apiFetch<ScanDetail>(`/vapt/scans/${id}`));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, [id]);
  useEffect(() => { void load(); }, [load]);

  const cancel = async () => {
    setBusy(true);
    try {
      await apiFetch(`/vapt/scans/${id}/cancel`, { method: "POST", body: "{}" });
      setNotice("Cancellation recorded — running stages stop at their next checkpoint and partial results are preserved (§128).");
      await load();
    } catch (e) { setError(e instanceof ApiError ? e.message : "Cancel failed."); } finally { setBusy(false); }
  };

  const pct = (v: number | null) => (v === null ? "not measured" : `${Math.round(v * 100)}%`);
  return (
    <main>
      <PageHeader eyebrow="Web & API VAPT V2" title="Scan detail" />
      {error ? <p role="alert">{error}</p> : null}
      {notice ? <p>{notice}</p> : null}
      {!detail ? <p>Loading…</p> : (
        <>
          <Card title="Status">
            <p>Canonical scan: {detail.scan ? `${detail.scan.status} · progress ${detail.scan.progress}%` : "not materialized (preflight-gated)"}</p>
            {detail.plan ? <p>Plan: {detail.plan.profileKey} · {detail.plan.status} · estimated request class {detail.plan.estimatedRequestClass}</p> : null}
            {detail.plan && detail.plan.status === "STARTED" ? <button disabled={busy} onClick={() => void cancel()}>Cancel scan</button> : null}
          </Card>
          {detail.plan ? (
            <Card title="Stages & tools (§12)">
              <p>Stages: {detail.plan.stages.join(" → ")}</p>
              <p>Tools: {detail.plan.allowedTools.join(", ") || "—"}</p>
              {detail.plan.blockedModules.length > 0 ? (
                <p>Blocked modules: {detail.plan.blockedModules.map((b) => `${b.slug} (${b.reason})`).join("; ")}</p>
              ) : null}
              <p>Budget: {JSON.stringify(detail.plan.budget)} · scope snapshot <code>{detail.plan.scopeSnapshotId}</code></p>
            </Card>
          ) : null}
          <Card title="Coverage (§147)">
            <ul>
              <li>Endpoints: {detail.coverage.testedEndpoints} tested of {detail.coverage.discoveredEndpoints} discovered — {pct(detail.coverage.endpointCoverage)}</li>
              <li>Parameters: {pct(detail.coverage.parameterCoverage)} · Authenticated: {pct(detail.coverage.authenticatedCoverage)}</li>
              <li>Evidence records: {detail.evidenceCount}</li>
            </ul>
            {detail.coverage.skipped.length > 0 ? (
              <>
                <p>Skipped tests:</p>
                <ul>{detail.coverage.skipped.map((s, i) => <li key={i}>{s.test} — {s.reason}</li>)}</ul>
              </>
            ) : null}
            {detail.coverage.limitations.length > 0 ? (
              <>
                <p>Limitations:</p>
                <ul>{detail.coverage.limitations.map((l, i) => <li key={i}>{l}</li>)}</ul>
              </>
            ) : <EmptyState title="No limitations recorded." body="" />}
          </Card>
          <p><Link href="/vapt/web">← Back to Web VAPT</Link></p>
        </>
      )}
    </main>
  );
}
