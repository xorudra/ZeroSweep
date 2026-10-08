"use client";

import { useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Card, EmptyState, StatCard } from "@dsrclone/ui";

/**
 * EASM dashboard (Prompt 29 §98). Every number comes from stored
 * EASM rows — candidates, certificates, drift. Discovered assets are
 * NOT authorized targets: the dashboard says so, in the UI, always.
 */
interface Overview {
  totalExternalAssets: number; newAssetsThisWeek: number; unknownAssets: number;
  internetFacingAssets: number; criticalExposures: number; kevExposure: number;
  sensitiveServices: number;
  certificateHealth: Record<string, number>;
  recentDrift: Array<Record<string, unknown>>;
  ownershipCoverage: { owned: number; denominator: number; ratio: number | null; definition: string };
}
interface Dashboard { overview: Overview; permissions: string[] }

export default function Page() {
  const [data, setData] = useState<Dashboard | null>(null);
  const [error, setError] = useState("");
  const [question, setQuestion] = useState("");
  const [answer, setAnswer] = useState<{ answer: string; citations: Array<{ label: string }> } | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setData(await apiFetch<Dashboard>("/easm/dashboard"));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const ask = async () => {
    setBusy(true);
    try {
      setAnswer(await apiFetch("/easm/ask", { method: "POST", body: JSON.stringify({ question }) }));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Ask failed.");
    } finally { setBusy(false); }
  };

  const o = data?.overview;
  return (
    <main>
      <PageHeader eyebrow="EASM" title="External Attack Surface (EASM)" />
      <p style={{ color: "var(--muted, #666)", maxWidth: 760 }}>
        What public assets belong to us, what changed, and what is unknown. Discovery is
        passive-first: a discovered asset is a <strong>candidate</strong> — never an authorized
        scan target — until ownership is verified and active testing is separately authorized.
      </p>
      {error ? <p role="alert">{error}</p> : null}
      {!o ? <p>Loading…</p> : (
        <>
          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: 12 }}>
            <StatCard label="External Assets" value={o.totalExternalAssets} />
            <StatCard label="New This Week" value={o.newAssetsThisWeek} />
            <StatCard label="Unknown Assets" value={o.unknownAssets} />
            <StatCard label="Internet-Facing" value={o.internetFacingAssets} />
            <StatCard label="Critical Exposures" value={o.criticalExposures} />
            <StatCard label="KEV Exposure" value={o.kevExposure} />
            <StatCard label="Sensitive Services" value={o.sensitiveServices} />
            <StatCard label="Certs Expiring/Urgent" value={(o.certificateHealth.EXPIRING ?? 0) + (o.certificateHealth.URGENT ?? 0) + (o.certificateHealth.EXPIRED ?? 0)} />
          </div>
          <Card title="Ownership coverage">
            <p>{o.ownershipCoverage.owned} of {o.ownershipCoverage.denominator} assets owned
              {o.ownershipCoverage.ratio !== null ? ` (${Math.round(o.ownershipCoverage.ratio * 100)}%)` : ""} — {o.ownershipCoverage.definition}.</p>
          </Card>
          <Card title="Recent drift">
            {o.recentDrift.length === 0 ? <EmptyState title="No open drift events." body="" /> : (
              <ul>
                {o.recentDrift.map((d) => (
                  <li key={String(d.id)}>
                    <strong>{String(d.type)}</strong> on {String(d.assetIdentity)} — {String(d.severity)} ({String(d.status)})
                  </li>
                ))}
              </ul>
            )}
            <p><Link href="/easm/drift">Open the drift queue</Link> · <Link href="/easm/unknown-assets">Review unknown assets</Link> · <Link href="/easm/discovery">Programs &amp; discovery</Link></p>
          </Card>
          <Card title="Ask the EASM copilot">
            <p style={{ color: "var(--muted, #666)" }}>
              Grounded in EASM records only. It can suggest ownership from evidence — it cannot
              verify ownership or authorize scanning.
            </p>
            <div style={{ display: "flex", gap: 8 }}>
              <input value={question} onChange={(e) => setQuestion(e.target.value)} placeholder="What new public assets appeared this week?" style={{ flex: 1 }} />
              <button onClick={ask} disabled={busy || question.length < 3}>Ask</button>
            </div>
            {answer ? (
              <div>
                <p>{answer.answer}</p>
                {answer.citations.length > 0 ? <p>Cited: {answer.citations.map((c) => c.label).join(", ")}</p> : null}
              </div>
            ) : null}
          </Card>
        </>
      )}
    </main>
  );
}
