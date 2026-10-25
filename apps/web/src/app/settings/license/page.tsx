"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@zerosweep/ui";
function Button({ children, onClick, variant, disabled }: { children: React.ReactNode; onClick?: () => void; variant?: string; disabled?: boolean }) {
  return (
    <button onClick={onClick} disabled={disabled} className={variant === "secondary" ? "rounded border border-slate-700 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-800 disabled:opacity-50" : "rounded bg-cyan-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-cyan-500 disabled:opacity-50"}>
      {children}
    </button>
  );
}


/**
 * License view (Prompt 40 §110–§112): installed license state for
 * self-hosted/enterprise deployments. The application verifies
 * signatures with the embedded PUBLIC key only; invalid licenses are
 * rejected and never silently accepted (§33).
 */
interface LicenseView {
  installed: boolean; licensingEnabled: boolean;
  license: { licenseId: string; edition: string; organization: string; issuer: string; expiresAt: string; revokedAt: string | null } | null;
  evaluation: { status: string; capabilitiesActive: boolean; inGracePeriod: boolean; graceUntil: string | null; reasons: string[] } | null;
}

const STATUS_TONE: Record<string, string> = {
  VALID: "text-emerald-300", EXPIRING: "text-amber-300", EXPIRED: "text-red-300",
  INVALID: "text-red-300", REVOKED: "text-red-300", NOT_YET_VALID: "text-amber-300",
};

export default function Page() {
  const [view, setView] = useState<LicenseView | null>(null);
  const [document, setDocument] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const load = useCallback(async () => {
    try {
      setView(await apiFetch<LicenseView>("/product/license"));
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  async function install() {
    setError(""); setNotice("");
    try {
      await apiFetch("/product/license/install", { method: "POST", body: JSON.stringify({ document }) });
      setNotice("License installed and verified.");
      setDocument("");
      await load();
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "License installation failed.");
    }
  }

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Settings" title="License" body="Product license for this deployment. License failure restricts paid capabilities — it never deletes data and never breaks sign-in or export (§36)." />
      {error && <Card><p className="text-sm text-red-300">{error}</p></Card>}
      {notice && <Card><p className="text-sm text-emerald-300">{notice}</p></Card>}
      {!view && !error && <EmptyState title="Loading license…" body="Fetching license state." />}
      {view && !view.licensingEnabled && (
        <EmptyState title="Licensing is not enabled in this deployment" body="No license verification key is configured, so no license is required here. Entitlements come from your plan/subscription instead." />
      )}
      {view && view.licensingEnabled && (
        <>
          <Card>
            <div className="flex flex-wrap items-center gap-3">
              <h2 className="text-base font-semibold">License status</h2>
              {view.evaluation ? (
                <span className={`font-semibold ${STATUS_TONE[view.evaluation.status] ?? ""}`}>{view.evaluation.status}</span>
              ) : <Badge>NOT INSTALLED</Badge>}
              {view.evaluation?.inGracePeriod && <Badge>Grace period until {view.evaluation.graceUntil ? new Date(view.evaluation.graceUntil).toLocaleDateString() : ""}</Badge>}
            </div>
            {view.license && (
              <dl className="mt-3 grid gap-1 text-sm text-slate-300 sm:grid-cols-2">
                <div>License ID: {view.license.licenseId}</div>
                <div>Edition: {view.license.edition}</div>
                <div>Licensed to: {view.license.organization}</div>
                <div>Issuer: {view.license.issuer}</div>
                <div>Expires: {new Date(view.license.expiresAt).toLocaleDateString()}</div>
                {view.license.revokedAt && <div>Revoked: {new Date(view.license.revokedAt).toLocaleDateString()}</div>}
              </dl>
            )}
            {view.evaluation && view.evaluation.reasons.length > 0 && (
              <ul className="mt-2 list-disc pl-5 text-sm text-slate-400">
                {view.evaluation.reasons.map((r) => <li key={r}>{r}</li>)}
              </ul>
            )}
          </Card>
          <Card>
            <h2 className="mb-2 text-base font-semibold">Install / renew license</h2>
            <p className="mb-2 text-sm text-slate-400">Paste the signed license document (JSON). Tampered or unsigned documents are rejected and the rejection is audited (§32/§33).</p>
            <textarea
              className="w-full rounded border border-slate-700 bg-slate-900 p-2 font-mono text-xs"
              rows={8}
              value={document}
              onChange={(e) => setDocument(e.target.value)}
              placeholder='{"version":1,"payload":{…},"signature":"…"}'
            />
            <div className="mt-2"><Button onClick={() => void install()} disabled={!document.trim()}>Verify &amp; install</Button></div>
          </Card>
        </>
      )}
    </div>
  );
}
