"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { Badge, Card, EmptyState } from "@zerosweep/ui";
import { apiFetch, ApiError } from "@/lib/api-client";

interface Detail {
  component: { id: string; name: string; version?: string; ecosystem: string; purl: string; scope: string; bindingLabel: string; licenses: string[]; supplier: string | null };
  vulnerabilities: { cveId: string; matchType: string; confidence: string; affectedStatus: string; reachability: string; firstMatchedAt: string }[];
  linkedFindings: { id: string; title: string; status: string; cve: string | null; riskScore: number | null }[];
}

/** Component detail (Prompt 30 §96): identity, appearances, matches. */
export default function Page() {
  const params = useParams<{ id: string }>();
  const [detail, setDetail] = useState<Detail | null>(null);
  const [error, setError] = useState<string | null>(null);
  useEffect(() => {
    apiFetch<Detail>(`/vulnerability-intelligence/components/${encodeURIComponent(params.id)}`).then(setDetail).catch((e: unknown) => setError(e instanceof ApiError ? e.message : "Could not load this component."));
  }, [params.id]);
  if (error) return <EmptyState title="Component unavailable" body={error} />;
  if (!detail) return <p className="text-sm text-slate-400">Loading…</p>;
  const c = detail.component;
  return (
    <>
      <PageHeader eyebrow="Software Supply Chain" title={`${c.name}${c.version ? `@${c.version}` : ""}`} body={`PURL ${c.purl} · ecosystem ${c.ecosystem} · scope ${c.scope} · appears in ${c.bindingLabel}${c.licenses.length ? ` · licenses ${c.licenses.join(", ")}` : ""}`} />
      <Card>
        <h3 className="text-sm font-semibold text-slate-200">Vulnerability matches</h3>
        {detail.vulnerabilities.length === 0 ? <p className="mt-1 text-sm text-slate-500">No correlation results for this component yet — run correlation from the SBOM explorer.</p> : (
          <ul className="mt-2 space-y-2 text-sm text-slate-300">
            {detail.vulnerabilities.map((v) => (
              <li key={v.cveId}>
                <Link className="text-sky-300 hover:underline" href={`/vulnerabilities/cve/${v.cveId}`}>{v.cveId}</Link>
                {" "}<Badge tone={v.affectedStatus === "AFFECTED" ? "CRITICAL" : "DEFAULT"}>{v.affectedStatus}</Badge>
                {" · "}match {v.matchType} ({v.confidence}) · reachability {v.reachability} · since {v.firstMatchedAt.slice(0, 10)}
              </li>
            ))}
          </ul>
        )}
      </Card>
      <Card>
        <h3 className="text-sm font-semibold text-slate-200">Linked findings</h3>
        {detail.linkedFindings.length === 0 ? <p className="mt-1 text-sm text-slate-500">No findings reference this component's PURL.</p> : (
          <ul className="mt-2 space-y-1 text-sm text-slate-300">
            {detail.linkedFindings.map((f) => <li key={f.id}>{f.title} · {f.status} · risk {f.riskScore ?? "—"}</li>)}
          </ul>
        )}
      </Card>
    </>
  );
}
