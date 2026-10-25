"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { Card, EmptyState } from "@zerosweep/ui";
import { apiFetch } from "@/lib/api-client";

interface Regression {
  id: string; caseId: string; findingId: string; fingerprint: string | null;
  detectedAt: string; previousVerifiedAt: string | null; source: string;
}

/**
 * Vulnerability regressions (Prompt 31 §108). A verified-fixed issue
 * that reappears reopens — it is never silently re-closed, and fix
 * durability is measured from these events.
 */
export default function Page() {
  const [rows, setRows] = useState<Regression[]>([]);
  useEffect(() => {
    apiFetch<Regression[]>("/remediation/regressions").then(setRows).catch(() => setRows([]));
  }, []);
  return (
    <>
      <PageHeader eyebrow="Remediation" title="Regressions" body="Previously verified fixes that came back. Each event reopened its case and finding, recalculated risk, and notified the owner." />
      <Card>
        {rows.length === 0 ? (
          <EmptyState title="No regressions recorded" body="When a scanner re-observes a fingerprint that was verified fixed, the regression appears here with its before/after evidence." />
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-slate-400"><th className="py-1">Detected</th><th>Case</th><th>Source</th><th>Previously verified</th><th>Fingerprint</th></tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id} className="border-t border-slate-800">
                  <td className="py-2">{new Date(r.detectedAt).toLocaleString()}</td>
                  <td><Link href={`/remediation/${r.caseId}`} className="text-sky-300 hover:underline">{r.caseId.slice(0, 8)}…</Link></td>
                  <td>{r.source}</td>
                  <td>{r.previousVerifiedAt ? new Date(r.previousVerifiedAt).toLocaleString() : "—"}</td>
                  <td className="text-slate-400">{r.fingerprint ? `${r.fingerprint.slice(0, 16)}…` : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </>
  );
}
