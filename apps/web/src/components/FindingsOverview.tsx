"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { Badge, Card, EmptyState, StatCard } from "@dsrclone/ui";
import { api } from "@/lib/api-client";

interface Summary {
  total: number;
  bySeverity: Record<string, number>;
  byVerificationStatus: Record<string, number>;
  topVulnerabilities: { id: string; title: string; severity: string; riskScore: number | null; host: string | null; sources: string[]; status: string }[];
}

/**
 * Overview findings panel (Prompt 7 §44): severity counts + top
 * vulnerabilities computed from REAL persisted findings via
 * GET /findings/summary. Zero findings renders the honest empty state —
 * numbers are never invented.
 */
export function FindingsOverview() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    api.findingsSummary()
      .then((s) => { if (!cancelled) setSummary(s as Summary); })
      .catch(() => { if (!cancelled) setFailed(true); });
    return () => { cancelled = true; };
  }, []);

  if (failed) {
    return (
      <Card eyebrow="Findings" title="Findings overview">
        <EmptyState title="Findings unavailable" body="The API could not be reached. When it is running, real finding counts appear here — never placeholder numbers." />
      </Card>
    );
  }
  if (!summary) return <p className="text-sm text-[#5d5f60]">Loading findings overview…</p>;
  if (summary.total === 0) {
    return (
      <Card eyebrow="Findings" title="Findings overview">
        <EmptyState title="No findings yet" body="Run an approved scan with the safe vulnerability detection stage (WEB_BASELINE or WEB_COMPREHENSIVE). Findings, severity counts and top vulnerabilities will appear here — only from real scanner output." />
      </Card>
    );
  }
  const sev = summary.bySeverity;
  return (
    <div className="space-y-4">
      <div className="grid grid-cols-2 gap-4 lg:grid-cols-5">
        <StatCard label="Critical" value={sev.CRITICAL ?? 0} hint="findings" />
        <StatCard label="High" value={sev.HIGH ?? 0} hint="findings" />
        <StatCard label="Medium" value={sev.MEDIUM ?? 0} hint="findings" />
        <StatCard label="Low" value={sev.LOW ?? 0} hint="findings" />
        <StatCard label="Informational" value={sev.INFORMATIONAL ?? 0} hint="findings" />
      </div>
      <Card eyebrow="Findings" title="Top vulnerabilities (by deterministic risk score)">
        <ul className="divide-y divide-[#f0f1f2]">
          {summary.topVulnerabilities.map((f) => (
            <li key={f.id} className="flex flex-wrap items-center gap-3 py-2 text-sm">
              <Badge tone={f.severity}>{f.severity}</Badge>
              <Link href={`/findings/${f.id}`} className="text-[#1b6c80] hover:underline">{f.title}</Link>
              <span className="text-[#5d5f60]">{f.host ?? ""}</span>
              <span className="ml-auto text-[#5d5f60]">
                {typeof f.riskScore === "number" ? `Risk ${f.riskScore}/100 · ` : ""}{f.sources.join(", ")} · {f.status}
              </span>
            </li>
          ))}
        </ul>
      </Card>
    </div>
  );
}
