"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { Badge, Card, EmptyState } from "@zerosweep/ui";
import { apiFetch, ApiError } from "@/lib/api-client";

interface KevItem {
  cveId: string; vendorProject: string | null; product: string | null;
  dateAdded: string | null; dueDate: string | null; overdue: boolean;
  ransomwareAssociation: string | null; requiredAction: string | null;
  affectedFindings: number; internetFacingFindings: number; affectsThisWorkspace: boolean;
}
interface KevDashboard { totalKevCatalog: number; items: KevItem[]; recentEvents: { cveId: string; eventType: string; occurredAt: string; source: string }[] }

/** KEV console (Prompt 30 §99): catalog state joined to this workspace. */
export default function Page() {
  const [data, setData] = useState<KevDashboard | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    apiFetch<KevDashboard>("/vulnerability-intelligence/kev").then(setData).catch((e: unknown) => setError(e instanceof ApiError ? e.message : "Could not load the KEV console."));
  }, []);
  if (error) return <EmptyState title="KEV console unavailable" body={error} />;
  if (!data) return <p className="text-sm text-slate-400">Loading…</p>;
  const affecting = data.items.filter((i) => i.affectsThisWorkspace);
  return (
    <>
      <PageHeader eyebrow="Vulnerability Intelligence" title="CISA KEV Console" body={`${data.totalKevCatalog} entries in the local known-exploited-vulnerabilities catalog; ${affecting.length} affect this workspace. A CVE becoming KEV-listed re-evaluates affected findings and notifies per policy.`} />
      <Card>
        <h3 className="text-sm font-semibold text-slate-200">Affecting this workspace</h3>
        {affecting.length === 0 ? <p className="mt-1 text-sm text-slate-500">No KEV-listed CVE currently matches a finding in this workspace.</p> : (
          <ul className="mt-2 space-y-2 text-sm text-slate-300">
            {affecting.map((i) => (
              <li key={i.cveId}>
                <Link className="text-sky-300 hover:underline" href={`/vulnerabilities/cve/${i.cveId}`}>{i.cveId}</Link>
                {" "}<Badge tone="CRITICAL">KEV</Badge>{i.overdue ? <Badge tone="CRITICAL">OVERDUE</Badge> : null}
                {" · "}{i.vendorProject ?? ""} {i.product ?? ""} · added {i.dateAdded ?? "—"} · due {i.dueDate ?? "—"}
                {" · "}{i.affectedFindings} finding(s), {i.internetFacingFindings} internet-facing
                {i.ransomwareAssociation ? ` · ransomware: ${i.ransomwareAssociation}` : ""}
                {i.requiredAction ? <><br /><span className="text-slate-500">{i.requiredAction}</span></> : null}
              </li>
            ))}
          </ul>
        )}
      </Card>
      <Card>
        <h3 className="text-sm font-semibold text-slate-200">Recent catalog events</h3>
        {data.recentEvents.length === 0 ? <p className="mt-1 text-sm text-slate-500">No catalog transitions recorded yet.</p> : (
          <ul className="mt-2 space-y-1 text-sm text-slate-300">
            {data.recentEvents.map((e, i) => <li key={i}><Badge>{e.eventType}</Badge> <Link className="text-sky-300 hover:underline" href={`/vulnerabilities/cve/${e.cveId}`}>{e.cveId}</Link> · {e.occurredAt.slice(0, 10)} · {e.source}</li>)}
          </ul>
        )}
      </Card>
      <Card>
        <h3 className="text-sm font-semibold text-slate-200">Full catalog (local records)</h3>
        <ul className="mt-2 space-y-1 text-sm text-slate-400">
          {data.items.filter((i) => !i.affectsThisWorkspace).slice(0, 50).map((i) => <li key={i.cveId}><Link className="text-sky-300 hover:underline" href={`/vulnerabilities/cve/${i.cveId}`}>{i.cveId}</Link> · {i.vendorProject ?? ""} {i.product ?? ""} · due {i.dueDate ?? "—"}</li>)}
        </ul>
      </Card>
    </>
  );
}
