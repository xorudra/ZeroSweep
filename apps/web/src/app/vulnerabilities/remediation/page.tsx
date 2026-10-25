"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { Badge, Card, EmptyState } from "@zerosweep/ui";
import { apiFetch, ApiError } from "@/lib/api-client";

interface QueueItem {
  findingId: string; title: string; cveId: string;
  priorityScore: number; priorityBand: string; why: string[]; riskSignals: string[];
  cvss: number | null; epss: number | null; kevListed: boolean; kevDueDate: string | null;
  internetExposed: boolean; assetCriticality: string; assetName: string | null; owner: string | null;
  patchStatus: string; fixedVersion: string | null;
  recommendedAction: string; recommendationReason: string;
  slaDueAt: string | null; slaBreached: boolean; ageDays: number;
}

/**
 * Remediation queue (Prompt 30 §94): deterministic multi-factor
 * priority — never CVSS alone — with the explanation on every row.
 */
export default function Page() {
  const [items, setItems] = useState<QueueItem[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    apiFetch<{ items: QueueItem[] }>("/vulnerability-intelligence/remediation").then((r) => setItems(r.items)).catch((e: unknown) => setError(e instanceof ApiError ? e.message : "Could not load the remediation queue."));
  }, []);
  if (error) return <EmptyState title="Remediation queue unavailable" body={error} />;
  if (!items) return <p className="text-sm text-slate-400">Loading…</p>;
  return (
    <>
      <PageHeader eyebrow="Vulnerability Intelligence" title="Remediation Queue" body="Ranked by KEV status, EPSS, exposure, asset criticality, reachability, exploit maturity and blast radius — CVSS is one signal among many, and every ranking explains itself." />
      {items.length === 0 ? <EmptyState title="Queue is empty" body="No open CVE-carrying findings in this workspace." /> : (
        <div className="space-y-3">
          {items.map((i) => (
            <Card key={i.findingId}>
              <div className="flex flex-wrap items-center gap-2">
                <Badge tone={i.priorityBand === "P0" || i.priorityBand === "P1" ? "CRITICAL" : "DEFAULT"}>{i.priorityBand} · {i.priorityScore}</Badge>
                <Link className="text-sky-300 hover:underline" href={`/vulnerabilities/cve/${i.cveId}`}>{i.cveId}</Link>
                {i.kevListed ? <Badge tone="CRITICAL">KEV{i.kevDueDate ? ` due ${i.kevDueDate}` : ""}</Badge> : null}
                {i.slaBreached ? <Badge tone="CRITICAL">SLA BREACHED</Badge> : null}
                <span className="text-sm text-slate-300">{i.title}</span>
              </div>
              <p className="mt-1 text-xs text-slate-400">
                CVSS {i.cvss ?? "unrecorded"} · EPSS {i.epss ?? "absent"} · {i.internetExposed ? "internet-exposed" : "internal"} · asset {i.assetName ?? "—"} ({i.assetCriticality}) · patch: {i.patchStatus}{i.fixedVersion ? ` → ${i.fixedVersion}` : ""} · age {i.ageDays}d{i.slaDueAt ? ` · SLA ${i.slaDueAt.slice(0, 10)}` : ""}
              </p>
              <p className="mt-1 text-sm text-slate-200">Recommended: <strong>{i.recommendedAction}</strong> — {i.recommendationReason}</p>
              <ul className="mt-1 list-inside list-disc text-xs text-slate-500">
                {i.why.map((w, j) => <li key={j}>{w}</li>)}
              </ul>
            </Card>
          ))}
        </div>
      )}
    </>
  );
}
