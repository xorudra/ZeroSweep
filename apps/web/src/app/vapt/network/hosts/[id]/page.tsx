"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Card, EmptyState } from "@zerosweep/ui";

/**
 * Host detail (Prompt 33 §115): Overview / Network / Ports / Services /
 * OS / TLS / Findings / Evidence / Risk / Remediation / Timeline as
 * sections over the canonical asset + V2 observations. OS data keeps
 * its confidence band — a weak fingerprint is shown as a hint, never
 * as a confirmed OS (§42).
 */
interface HostDetail {
  host: { id: string; host: string; ip?: string | null; network?: string | null; osHint?: string | null; criticality?: string };
  services: Array<{ port: number; protocol: string; name?: string | null; product?: string | null; version?: string | null; state?: string | null; exposure: { exposure: string; riskSignal: string; sensitiveClass?: string }; verification: { method: string; rationale: string } }>;
  observations: Array<{ id: string; ip: string; discoveryMethod: string; scopeStatus: string; hostStatus: string; confidence: number }>;
  osObservations: Array<{ id: string; family: string; versionHint?: string | null; confidence: number; band: string; source: string }>;
  findings: Array<{ id: string; title: string; severity: string; cve?: string | null; status?: string }>;
}

const TABS = ["Overview", "Network", "Ports", "Services", "OS", "TLS", "Findings", "Evidence", "Risk", "Remediation", "Timeline"] as const;

export default function Page() {
  const params = useParams<{ id: string }>();
  const [detail, setDetail] = useState<HostDetail | null>(null);
  const [tab, setTab] = useState<(typeof TABS)[number]>("Overview");
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try { setDetail(await apiFetch<HostDetail>(`/vapt/network/hosts/${params.id}`)); }
    catch (e) { setError(e instanceof ApiError ? e.message : "Could not reach the API."); }
  }, [params.id]);

  useEffect(() => { void load(); }, [load]);

  if (!detail) return <main><PageHeader eyebrow="Network VAPT V2 · Host" title="Host" /><p>{error || "Loading…"}</p></main>;
  const h = detail.host;
  const tlsServices = detail.services.filter((s) => s.port === 443 || s.port === 8443 || (s.name ?? "").includes("https") || (s.name ?? "").includes("ssl"));
  return (
    <main>
      <PageHeader eyebrow="Network VAPT V2 · Host" title={h.host} />
      <p style={{ color: "var(--muted, #666)" }}>{h.ip ?? "no IP recorded"} · network {h.network ?? "—"} · criticality {h.criticality ?? "UNSPECIFIED"}</p>
      {error ? <p role="alert">{error}</p> : null}
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
        {TABS.map((t) => <button key={t} onClick={() => setTab(t)} aria-pressed={tab === t}>{t}</button>)}
      </div>

      {tab === "Overview" ? (
        <Card title="Overview">
          <p>{detail.services.length} service(s) recorded · {detail.findings.length} finding(s) · {detail.observations.length} discovery observation(s).</p>
          <p>Exposure signals are risk context (§97–§99) — an open port alone is never a vulnerability (§44).</p>
        </Card>
      ) : null}
      {tab === "Network" ? (
        <Card title="Network">
          <p>Network: {h.network ?? "—"}</p>
          <p>Observations (discovery never authorizes scanning, §21):</p>
          {detail.observations.length === 0 ? <EmptyState title="No V2 observations." body="Observations accumulate from governed discovery runs." /> : (
            <ul>{detail.observations.map((o) => <li key={o.id}>{o.ip} · {o.discoveryMethod} · scope {o.scopeStatus} · status {o.hostStatus} · confidence {o.confidence}</li>)}</ul>
          )}
        </Card>
      ) : null}
      {tab === "Ports" ? (
        <Card title="Ports">
          {detail.services.length === 0 ? <EmptyState title="No ports recorded." body="Port inventory comes from governed discovery." /> : (
            <ul>{detail.services.map((s) => <li key={`${s.port}-${s.protocol}`}>{s.port}/{s.protocol} — {s.state ?? "OPEN"}</li>)}</ul>
          )}
        </Card>
      ) : null}
      {tab === "Services" ? (
        <Card title="Services">
          {detail.services.length === 0 ? <EmptyState title="No services recorded." body="Service identification is bounded and evidence-based (§35–§39)." /> : (
            <ul>{detail.services.map((s) => <li key={`${s.port}-${s.protocol}`}>{s.port}/{s.protocol} — {s.name ?? "unknown"}{s.product ? ` · ${s.product}` : ""}{s.version ? ` ${s.version}` : ""} · exposure {s.exposure.exposure}{s.exposure.sensitiveClass ? ` · ${s.exposure.sensitiveClass}` : ""}</li>)}</ul>
          )}
        </Card>
      ) : null}
      {tab === "OS" ? (
        <Card title="OS fingerprint (§40–§42)">
          {detail.osObservations.length === 0 ? <EmptyState title="No OS observations." body={h.osHint ? `Asset hint only: ${h.osHint} (unverified).` : "No fingerprint evidence recorded."} /> : (
            <ul>{detail.osObservations.map((o) => <li key={o.id}>{o.family}{o.versionHint ? ` ${o.versionHint}` : ""} — confidence {o.confidence} ({o.band}) via {o.source}</li>)}</ul>
          )}
        </Card>
      ) : null}
      {tab === "TLS" ? (
        <Card title="TLS">
          {tlsServices.length === 0 ? <EmptyState title="No TLS services recorded." body="TLS posture is assessed by the TLS_NETWORK profile (§53/§54)." /> : (
            <ul>{tlsServices.map((s) => <li key={s.port}>{s.port}/{s.protocol} — {s.name ?? "tls"} · see TLS findings for certificate/protocol/cipher posture</li>)}</ul>
          )}
        </Card>
      ) : null}
      {tab === "Findings" ? (
        <Card title="Findings">
          {detail.findings.length === 0 ? <EmptyState title="No findings for this host." body="Findings arrive only via governed checks → normalization → correlation (§64–§70)." /> : (
            <ul>{detail.findings.map((f) => <li key={f.id}>{f.severity} — {f.title}{f.cve ? ` · ${f.cve}` : ""}{f.status ? ` · ${f.status}` : ""}</li>)}</ul>
          )}
        </Card>
      ) : null}
      {tab === "Evidence" ? (
        <Card title="Evidence">
          <p>Evidence is sanitized scanner output, banners (classification-redacted, §135), TLS metadata and plugin provenance — raw packet bytes never flow through this UI (§88/§89).</p>
        </Card>
      ) : null}
      {tab === "Risk" ? (
        <Card title="Risk context">
          <ul>{detail.services.map((s) => <li key={s.port}>{s.port}: {s.exposure.riskSignal}</li>)}</ul>
        </Card>
      ) : null}
      {tab === "Remediation" ? (
        <Card title="Remediation + verification (§110–§112)">
          {detail.services.length === 0 ? <EmptyState title="Nothing to verify." body="Verification plans are per-finding and minimal-scope." /> : (
            <ul>{detail.services.map((s) => <li key={s.port}>{s.port}: {s.verification.method} — {s.verification.rationale}</li>)}</ul>
          )}
          <p>Closure runs through the Prompt 31 lifecycle — VERIFIED_FIXED requires governed retest evidence.</p>
        </Card>
      ) : null}
      {tab === "Timeline" ? (
        <Card title="Timeline">
          <p>Host history is the observation + finding record above; baselines and drift events live on the Network VAPT dashboard (§101–§104).</p>
        </Card>
      ) : null}

      <p><Link href="/vapt/network/hosts">← All hosts</Link></p>
    </main>
  );
}
