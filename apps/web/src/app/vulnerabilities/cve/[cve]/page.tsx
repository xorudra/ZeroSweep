"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { Badge, Card, EmptyState } from "@dsrclone/ui";
import { apiFetch, ApiError } from "@/lib/api-client";

interface CveDetail {
  cveId: string;
  hasIntelligenceData: boolean;
  cve: { description?: string; cvss?: { baseScore: number; vector?: string; version: string }; cweIds?: string[]; references?: { label: string; url: string }[] } | null;
  epss: { score: number; percentile: number; date: string } | null;
  kev: { dateAdded?: string; vendorProject?: string; product?: string; requiredAction?: string; knownRansomwareUse?: string } | null;
  affectedAssets: { host: string | null; findings: number }[];
  affectedFindings: Record<string, unknown>[];
  syncStates: { source: string; status: string; records: number }[];
  exploitReferencesNote: string;
}

/**
 * CVE detail (Prompt 11 §69): description, CVSS, CWE, references, EPSS,
 * KEV, affected assets/findings and remediation priority context — all
 * from the governed LOCAL dataset. A CVE with no local record says so
 * plainly; reference data is never fetched live or invented (§87).
 */
export default function Page() {
  const params = useParams<{ cve: string }>();
  const [detail, setDetail] = useState<CveDetail | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiFetch<CveDetail>(`/cves/${encodeURIComponent(params.cve)}`)
      .then(setDetail)
      .catch((e: unknown) => setError(e instanceof ApiError ? e.message : "Could not load this CVE."));
  }, [params.cve]);

  if (error) return <EmptyState title="CVE unavailable" body={error} />;
  if (!detail) return <p className="text-sm text-slate-400">Loading…</p>;

  return (
    <>
      <PageHeader eyebrow="Vulnerability Intelligence" title={detail.cveId} body={detail.cve?.description ?? undefined} />
      {!detail.hasIntelligenceData ? (
        <EmptyState
          title="No local intelligence data for this CVE"
          body="The governed local dataset holds no CVE / EPSS / KEV record for this identifier yet, so nothing is shown — DSRclone never fills intelligence panels with inferred or live-fetched values. Affected findings in your workspace are still listed below. Sync state: see the intelligence sources on the Vulnerabilities page."
        />
      ) : (
        <div className="grid gap-4 md:grid-cols-3">
          <Card>
            <h3 className="text-sm font-semibold text-slate-200">CVSS</h3>
            {detail.cve?.cvss ? (
              <p className="mt-1 text-sm text-slate-300">{detail.cve.cvss.baseScore} · {detail.cve.cvss.version}{detail.cve.cvss.vector ? ` · ${detail.cve.cvss.vector}` : ""}</p>
            ) : <p className="mt-1 text-sm text-slate-500">No CVSS in the local record.</p>}
            <h3 className="mt-4 text-sm font-semibold text-slate-200">CWE</h3>
            <p className="mt-1 text-sm text-slate-300">{detail.cve?.cweIds?.join(", ") || "—"}</p>
          </Card>
          <Card>
            <h3 className="text-sm font-semibold text-slate-200">EPSS (FIRST)</h3>
            {detail.epss ? (
              <p className="mt-1 text-sm text-slate-300">Score {detail.epss.score.toFixed(3)} · percentile {detail.epss.percentile.toFixed(3)} · {detail.epss.date}<br /><span className="text-slate-500">EPSS is an exploitation probability — context for prioritization, never severity (§27).</span></p>
            ) : <p className="mt-1 text-sm text-slate-500">No EPSS record locally.</p>}
          </Card>
          <Card>
            <h3 className="text-sm font-semibold text-slate-200">CISA KEV</h3>
            {detail.kev ? (
              <p className="mt-1 text-sm text-slate-300"><Badge tone="CRITICAL">KEV LISTED</Badge> {detail.kev.vendorProject ?? ""} {detail.kev.product ?? ""}<br />{detail.kev.requiredAction ?? ""}</p>
            ) : <p className="mt-1 text-sm text-slate-500">Not in the local KEV catalog.</p>}
          </Card>
        </div>
      )}
      <p className="mt-3 text-xs text-slate-500">{detail.exploitReferencesNote}</p>
      {detail.cve?.references?.length ? (
        <Card>
          <h3 className="text-sm font-semibold text-slate-200">References</h3>
          <ul className="mt-2 space-y-1 text-sm">
            {detail.cve.references.map((r, i) => <li key={i}><a className="text-sky-300 hover:underline" href={r.url} target="_blank" rel="noreferrer">{r.label}</a></li>)}
          </ul>
        </Card>
      ) : null}
      <Card>
        <h3 className="text-sm font-semibold text-slate-200">Affected findings in this workspace</h3>
        {detail.affectedFindings.length === 0 ? (
          <p className="mt-1 text-sm text-slate-500">No findings in this workspace carry this CVE.</p>
        ) : (
          <ul className="mt-2 space-y-1 text-sm text-slate-300">
            {detail.affectedFindings.map((f, i) => (
              <li key={i}>
                <Link href={`/vulnerabilities/${String(f.id)}`} className="text-sky-300 hover:underline">{String(f.title)}</Link>
                {" · "}{String(f.host ?? "—")}{f.port ? `:${String(f.port)}` : ""} · {String(f.lifecycleStatus)} · {String(f.priority ?? "unprioritized")}
              </li>
            ))}
          </ul>
        )}
      </Card>
    </>
  );
}
