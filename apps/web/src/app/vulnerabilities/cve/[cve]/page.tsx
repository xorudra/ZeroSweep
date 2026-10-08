"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { Badge, Card, EmptyState } from "@dsrclone/ui";
import { apiFetch, ApiError } from "@/lib/api-client";

interface DeepIntel {
  hasRecord: boolean;
  status: string;
  provenance: Record<string, unknown>;
  cvssAssessments: { version: string; baseScore: number; source: string; vector?: string }[];
  preferredCvss?: { version: string; baseScore: number; source: string };
  epssPoints: { score: number; percentile: number; date: string }[];
  epssFreshness: string;
  kev?: { status: string; dateAdded?: string; dueDate?: string; requiredAction?: string; ransomwareAssociation?: string };
  ranges: { vendor: string; product: string; introducedVersion?: string; fixedVersion?: string; lastAffectedVersion?: string; source: string }[];
  affectedProducts: { vendor: string; product: string; identifier?: string }[];
  patch: { status: string; fixedVersion?: string; conflictingFixedVersions?: Record<string, unknown> };
  advisories: { provider: string; advisoryId: string; title: string }[];
  exploitContext?: { publicExploitKnown: boolean; exploitationObserved: boolean; exploitMaturity: string; source: string };
  conflicts: { id: string; conflictType: string; status: string }[];
  exposure: { componentsConfirmed: number; componentsPotential: number; componentsUnknown: number };
  blastRadius?: { confirmed: { components: number; assets: number }; potential: { components: number; assets: number } };
  noIntelligence?: string;
  intelSnapshotId: string;
}

/**
 * Prompt 30 deep intelligence: multi-source CVSS with provenance,
 * EPSS history, affected ranges, patch state, exploit context
 * (defensive metadata only), conflicts and blast radius — all from
 * governed records; the section renders nothing on API error.
 */
function DeepIntelSection({ cveId }: { cveId: string }) {
  const [deep, setDeep] = useState<DeepIntel | null>(null);
  useEffect(() => {
    apiFetch<DeepIntel>(`/vulnerability-intelligence/cves/${encodeURIComponent(cveId)}`).then(setDeep).catch(() => undefined);
  }, [cveId]);
  if (!deep) return null;
  return (
    <>
      <Card>
        <h3 className="text-sm font-semibold text-slate-200">Advanced intelligence (Prompt 30) · snapshot {deep.intelSnapshotId}</h3>
        {deep.noIntelligence ? <p className="mt-1 text-sm text-slate-400">{deep.noIntelligence}</p> : null}
        <p className="mt-1 text-xs text-slate-500">Status {deep.status} · provenance origin {String((deep.provenance as { snapshotOrigin?: string }).snapshotOrigin ?? "recorded feed")}</p>
        <h4 className="mt-3 text-sm font-semibold text-slate-200">CVSS assessments by source</h4>
        {deep.cvssAssessments.length === 0 ? <p className="text-sm text-slate-500">No CVSS assessments recorded.</p> : (
          <ul className="mt-1 space-y-1 text-sm text-slate-300">
            {deep.cvssAssessments.map((a, i) => <li key={i}>{a.baseScore} · v{a.version} · {a.source}{deep.preferredCvss && a.baseScore === deep.preferredCvss.baseScore && a.source === deep.preferredCvss.source ? <> <Badge>preferred</Badge></> : null}{a.vector ? ` · ${a.vector}` : ""}</li>)}
          </ul>
        )}
        <h4 className="mt-3 text-sm font-semibold text-slate-200">EPSS history ({deep.epssFreshness})</h4>
        {deep.epssPoints.length === 0 ? <p className="text-sm text-slate-500">No EPSS recorded — absence is never shown as 0.</p> : (
          <p className="mt-1 text-sm text-slate-300">{deep.epssPoints.map((p) => `${p.date}: ${p.score} (pct ${p.percentile})`).join(" → ")}</p>
        )}
        {deep.kev ? <p className="mt-2 text-sm text-slate-300">KEV: {deep.kev.status}{deep.kev.dateAdded ? ` · added ${deep.kev.dateAdded}` : ""}{deep.kev.dueDate ? ` · due ${deep.kev.dueDate}` : ""}{deep.kev.ransomwareAssociation ? ` · ransomware ${deep.kev.ransomwareAssociation}` : ""}</p> : null}
      </Card>
      <div className="grid gap-4 md:grid-cols-2">
        <Card>
          <h3 className="text-sm font-semibold text-slate-200">Affected products & version ranges</h3>
          {deep.affectedProducts.length === 0 ? <p className="mt-1 text-sm text-slate-500">No affected products recorded.</p> : (
            <ul className="mt-2 space-y-1 text-sm text-slate-300">
              {deep.affectedProducts.map((p, i) => <li key={i}>{p.vendor} · {p.product}{p.identifier ? ` · ${p.identifier}` : ""}</li>)}
            </ul>
          )}
          <ul className="mt-2 space-y-1 text-sm text-slate-400">
            {deep.ranges.map((r, i) => <li key={i}>{r.vendor}/{r.product}: {r.introducedVersion ? `≥ ${r.introducedVersion}` : "any"} → {r.fixedVersion ? `fixed ${r.fixedVersion}` : r.lastAffectedVersion ? `last affected ${r.lastAffectedVersion}` : "no fix bound"} ({r.source})</li>)}
          </ul>
          <h3 className="mt-4 text-sm font-semibold text-slate-200">Patch intelligence</h3>
          <p className="mt-1 text-sm text-slate-300"><Badge>{deep.patch.status}</Badge>{deep.patch.fixedVersion ? ` fixed in ${deep.patch.fixedVersion}` : ""}{deep.patch.conflictingFixedVersions ? " · sources disagree on the fixed version (§86) — none is presented as definitive" : ""}</p>
          {deep.advisories.length ? (
            <ul className="mt-2 space-y-1 text-sm text-slate-400">
              {deep.advisories.map((a, i) => <li key={i}>{a.provider} · {a.advisoryId} · {a.title}</li>)}
            </ul>
          ) : null}
        </Card>
        <Card>
          <h3 className="text-sm font-semibold text-slate-200">Exposure & blast radius (this workspace)</h3>
          <p className="mt-1 text-sm text-slate-300">Components: {deep.exposure.componentsConfirmed} confirmed · {deep.exposure.componentsPotential} potential · {deep.exposure.componentsUnknown} unknown — always counted separately.</p>
          {deep.blastRadius ? <p className="mt-1 text-sm text-slate-300">Blast radius: {deep.blastRadius.confirmed.components} confirmed components / {deep.blastRadius.confirmed.assets} assets; {deep.blastRadius.potential.components} potential components / {deep.blastRadius.potential.assets} assets.</p> : null}
          <h3 className="mt-4 text-sm font-semibold text-slate-200">Exploit context (defensive metadata only)</h3>
          {deep.exploitContext ? (
            <p className="mt-1 text-sm text-slate-300">Maturity {deep.exploitContext.exploitMaturity} · public exploit known: {String(deep.exploitContext.publicExploitKnown)} · exploitation observed: {String(deep.exploitContext.exploitationObserved)} · source {deep.exploitContext.source}. No exploit code is stored or executed — ever.</p>
          ) : <p className="mt-1 text-sm text-slate-500">No exploit context recorded from a trusted source.</p>}
          {deep.conflicts.filter((c) => c.status === "OPEN").length ? (
            <>
              <h3 className="mt-4 text-sm font-semibold text-slate-200">Open intelligence conflicts</h3>
              <ul className="mt-1 space-y-1 text-sm text-amber-300">
                {deep.conflicts.filter((c) => c.status === "OPEN").map((c) => <li key={c.id}>{c.conflictType} — values from all sources are preserved; the deterministic preferred value is used until review.</li>)}
              </ul>
            </>
          ) : null}
        </Card>
      </div>
    </>
  );
}

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
      <DeepIntelSection cveId={detail.cveId} />
    </>
  );
}
