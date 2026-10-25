"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Card, EmptyState } from "@zerosweep/ui";

/**
 * External asset detail (Prompt 29 §100): ownership evidence,
 * DNS history, services, HTTP exposure, technologies, relationships,
 * drift, and the promotion action. Promotion creates an UNVERIFIED
 * canonical asset — the standard verification gates still apply.
 */
interface Detail {
  candidate: {
    id: string; normalizedValue: string; type: string; status: string; lifecycle: string;
    ownershipStatus: string; ownershipConfidence: string; activeTestingStatus: string;
    exposureState: string; hold?: { dns: boolean; screenshot: boolean; activeProbing: boolean };
    promotedTargetId: string | null; promotedAssetId: string | null;
  };
  observations: Array<Record<string, unknown>>;
  ownershipEvidence: Array<Record<string, unknown>>;
  dns: Array<Record<string, unknown>>;
  services: Array<Record<string, unknown>>;
  http: Array<Record<string, unknown>>;
  technologies: Array<Record<string, unknown>>;
  relationships: Array<Record<string, unknown>>;
  drift: Array<Record<string, unknown>>;
  screenshots: Array<Record<string, unknown>>;
  findings: Array<Record<string, unknown>>;
  danglingDns: Array<Record<string, unknown>>;
  canPromote: { ok: boolean; reason: string };
}

export default function Page() {
  const params = useParams<{ id: string }>();
  const [detail, setDetail] = useState<Detail | null>(null);
  const [error, setError] = useState("");
  const [message, setMessage] = useState("");

  const load = useCallback(async () => {
    try {
      setDetail(await apiFetch<Detail>(`/easm/assets/${params.id}`));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, [params.id]);

  useEffect(() => { void load(); }, [load]);

  const act = async (action: string) => {
    try {
      if (action === "PROMOTE") {
        await apiFetch(`/easm/candidates/${params.id}/promote`, { method: "POST", body: JSON.stringify({}) });
        setMessage("Promoted to a canonical asset — still UNVERIFIED; standard target verification and assessment approval still apply before any scan.");
      } else {
        await apiFetch(`/easm/candidates/${params.id}`, { method: "PATCH", body: JSON.stringify({ action }) });
        setMessage(`Updated (${action}).`);
      }
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Action failed.");
    }
  };

  const c = detail?.candidate;
  return (
    <main>
      <PageHeader eyebrow="EASM" title={c ? `Asset: ${c.normalizedValue}` : "External Asset"} />
      {error ? <p role="alert">{error}</p> : null}
      {message ? <p>{message}</p> : null}
      {!detail || !c ? <p>Loading…</p> : (
        <>
          <Card title="Status">
            <dl>
              <dt>Type</dt><dd>{c.type}</dd>
              <dt>Ownership</dt><dd>{c.ownershipStatus} ({c.ownershipConfidence})</dd>
              <dt>Active testing</dt><dd>{c.activeTestingStatus}</dd>
              <dt>Exposure</dt><dd>{c.exposureState}</dd>
              <dt>Lifecycle</dt><dd>{c.lifecycle}</dd>
              <dt>Review status</dt><dd>{c.status}</dd>
              <dt>Promoted target</dt><dd>{c.promotedTargetId ?? "—"}</dd>
            </dl>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              <button onClick={() => act("PROMOTE")} disabled={!detail.canPromote.ok}>Promote to managed asset</button>
              {!detail.canPromote.ok ? <span>Promotion blocked: {detail.canPromote.reason}</span> : null}
              <button onClick={() => act("CONFIRM")}>Confirm ownership</button>
              <button onClick={() => act("DECLARE_THIRD_PARTY")}>Declare third-party</button>
              <button onClick={() => act("DECLARE_SHARED")}>Declare shared</button>
              <button onClick={() => act("REJECT")}>Reject</button>
            </div>
          </Card>
          <Card title="Ownership evidence">
            {detail.ownershipEvidence.length === 0 ? <EmptyState title="No ownership evidence recorded yet." body="" /> : (
              <ul>{detail.ownershipEvidence.map((e, i) => <li key={i}>{String(e.kind)} — weight {String(e.weight)}</li>)}</ul>
            )}
          </Card>
          <Card title="DNS history">
            {detail.dns.length === 0 ? <EmptyState title="No DNS snapshots recorded." body="" /> : (
              <ul>{detail.dns.map((d, i) => <li key={i}>{String(d.domain)} — {JSON.stringify(d.records)} (hash {String(d.snapshotHash).slice(0, 8)})</li>)}</ul>
            )}
            {detail.danglingDns.length > 0 ? <p><strong>Dangling DNS candidate:</strong> CNAME target does not resolve — reported as a candidate with evidence, never as a proven takeover.</p> : null}
          </Card>
          <Card title="Observed services">
            {detail.services.length === 0 ? <EmptyState title="No approved service observations. Unapproved probing is never run." body="" /> : (
              <ul>{detail.services.map((s, i) => <li key={i}>{String(s.port)}/{String(s.transport)} {String(s.service ?? "")} {s.sensitiveClass ? `— sensitive: ${String(s.sensitiveClass)}` : ""}</li>)}</ul>
            )}
          </Card>
          <Card title="HTTP exposure">
            {detail.http.length === 0 ? <EmptyState title="No HTTP snapshots recorded." body="" /> : (
              <ul>{detail.http.map((h, i) => <li key={i}>{String(h.statusCode ?? "—")} {String(h.url)} {h.title ? `— ${String(h.title)}` : ""} {h.redirectTarget ? `→ redirects to ${String(h.redirectTarget)} (recorded, not followed)` : ""}</li>)}</ul>
            )}
          </Card>
          <Card title="Technologies">
            {detail.technologies.length === 0 ? <EmptyState title="No technology observations." body="" /> : (
              <ul>{detail.technologies.map((t, i) => <li key={i}>{String(t.displayName)} {t.version ? `v${String(t.version)}` : "(family only — version not asserted)"} — confidence {String(t.confidence)}</li>)}</ul>
            )}
          </Card>
          <Card title="Relationships">
            {detail.relationships.length === 0 ? <EmptyState title="No relationships recorded." body="" /> : (
              <ul>{detail.relationships.map((r, i) => <li key={i}>{String(r.type)} → {String(r.toIdentity)} ({String(r.source)})</li>)}</ul>
            )}
          </Card>
          <Card title="Drift & findings">
            {detail.drift.length === 0 ? <EmptyState title="No drift events for this asset." body="" /> : (
              <ul>{detail.drift.map((d, i) => <li key={i}>{String(d.type)} — {String(d.severity)} ({String(d.status)})</li>)}</ul>
            )}
            {detail.findings.length === 0 ? <p>No linked vulnerability findings.</p> : (
              <ul>{detail.findings.map((f, i) => <li key={i}>{String(f.title)} — {String(f.severity)} ({String(f.status)})</li>)}</ul>
            )}
          </Card>
        </>
      )}
    </main>
  );
}
