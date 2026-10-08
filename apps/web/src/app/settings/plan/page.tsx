"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { apiFetch, ApiError } from "@/lib/api-client";
import { Badge, Card, EmptyState } from "@dsrclone/ui";
function Button({ children, onClick, variant, disabled }: { children: React.ReactNode; onClick?: () => void; variant?: string; disabled?: boolean }) {
  return (
    <button onClick={onClick} disabled={disabled} className={variant === "secondary" ? "rounded border border-slate-700 px-3 py-1.5 text-sm text-slate-200 hover:bg-slate-800 disabled:opacity-50" : "rounded bg-cyan-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-cyan-500 disabled:opacity-50"}>
      {children}
    </button>
  );
}


/**
 * Plan view (Prompt 40 §107/§113–§118): current plan, entitlements,
 * features and limits; upgrade applies immediately; downgrade first
 * shows an impact preview and never deletes data.
 */
interface Entitlement { featureKey: string; enabled: boolean; limit: number | null; source: string }
interface Me {
  productMode: string; enforcementActive: boolean;
  entitlements: Entitlement[];
  subscription: { status: string; planCode: string | null; planVersionId: string; currentPeriodEnd: string | null; cancelAtPeriodEnd: boolean } | null;
  trial: { status: string; expiresAt: string } | null;
}
interface PlanVersion { id: string; version: number; quotas: Record<string, number | null>; entitlements: Array<{ featureKey: string; enabled: boolean; limit: number | null }> }
interface Plan { id: string; code: string; name: string; description: string | null; productMode: string; versions: PlanVersion[] }
interface Impact { dataDeleted: boolean; disabledFeatures: string[]; overLimitDimensions: Array<{ dimension: string; currentUsage: number; newLimit: number }>; resultsInOverLimit: boolean }

export default function Page() {
  const [me, setMe] = useState<Me | null>(null);
  const [plans, setPlans] = useState<Plan[]>([]);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [impact, setImpact] = useState<Impact | null>(null);
  const [pendingVersion, setPendingVersion] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const [m, p] = await Promise.all([
        apiFetch<Me>("/product/me"),
        apiFetch<{ items: Plan[] }>("/product/plans"),
      ]);
      setMe(m); setPlans(p.items ?? []);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API.");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  async function upgrade(planVersionId: string) {
    setError(""); setNotice("");
    try {
      await apiFetch("/product/subscription/upgrade", { method: "POST", body: JSON.stringify({ planVersionId }) });
      setNotice("Plan upgraded — the change applies immediately (§113).");
      await load();
    } catch (e) { setError(e instanceof ApiError ? e.message : "Upgrade failed."); }
  }

  async function previewDowngrade(planVersionId: string) {
    setError("");
    try {
      const res = await apiFetch<{ impact: Impact }>("/product/subscription/downgrade/preview", { method: "POST", body: JSON.stringify({ planVersionId }) });
      setImpact(res.impact); setPendingVersion(planVersionId);
    } catch (e) { setError(e instanceof ApiError ? e.message : "Preview failed."); }
  }

  async function confirmDowngrade() {
    if (!pendingVersion) return;
    try {
      await apiFetch("/product/subscription/downgrade", { method: "POST", body: JSON.stringify({ planVersionId: pendingVersion, impactAcknowledged: true }) });
      setNotice("Plan downgraded. No data was deleted; over-limit dimensions are read/export-only until usage fits the new limits (§116/§118).");
      setImpact(null); setPendingVersion(null);
      await load();
    } catch (e) { setError(e instanceof ApiError ? e.message : "Downgrade failed."); }
  }

  async function cancel() {
    try {
      await apiFetch("/product/subscription/cancel", { method: "POST", body: JSON.stringify({ atPeriodEnd: true }) });
      setNotice("Subscription will cancel at the end of the current period. Data is retained per the retention policy (§88).");
      await load();
    } catch (e) { setError(e instanceof ApiError ? e.message : "Cancellation failed."); }
  }

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Settings" title="Plan & entitlements" body="Your organization's plan, effective entitlements and subscription state. Entitlements are enforced by the API — this page only reflects them (§12)." />
      {error && <Card><p className="text-sm text-red-300">{error}</p></Card>}
      {notice && <Card><p className="text-sm text-emerald-300">{notice}</p></Card>}
      {!me && !error && <EmptyState title="Loading plan…" body="Fetching your organization's plan state." />}
      {me && (
        <>
          <Card>
            <div className="flex flex-wrap items-center gap-3">
              <h2 className="text-base font-semibold">{me.subscription?.planCode ?? "No plan"}</h2>
              {me.subscription && <Badge>{me.subscription.status}</Badge>}
              <Badge>{me.productMode}</Badge>
              {me.trial && <Badge>Trial {me.trial.status} · ends {new Date(me.trial.expiresAt).toLocaleDateString()}</Badge>}
              <span className="text-sm text-slate-400">{me.enforcementActive ? "Entitlement enforcement active" : "Deployment default entitlements (no product state on this organization)"}</span>
            </div>
            {me.subscription && (
              <div className="mt-3 flex gap-2">
                <Button variant="secondary" onClick={() => void cancel()}>Cancel at period end</Button>
              </div>
            )}
          </Card>
          <Card>
            <h2 className="mb-3 text-base font-semibold">Effective entitlements</h2>
            <ul className="grid gap-2 sm:grid-cols-2">
              {me.entitlements.map((e) => (
                <li key={e.featureKey} className="flex items-center justify-between rounded border border-slate-800 px-3 py-2 text-sm">
                  <span>{e.featureKey.replaceAll("_", " ")}</span>
                  <span className="flex items-center gap-2 text-slate-400">
                    {e.limit !== null && <span>limit {e.limit}</span>}
                    <Badge>{e.enabled ? "Enabled" : "Not entitled"}</Badge>
                  </span>
                </li>
              ))}
            </ul>
          </Card>
          <Card>
            <h2 className="mb-3 text-base font-semibold">Available plans</h2>
            <div className="grid gap-3 md:grid-cols-2">
              {plans.map((p) => {
                const latest = p.versions?.[0];
                const isCurrent = latest && me.subscription?.planVersionId === latest.id;
                return (
                  <div key={p.id} className="rounded border border-slate-800 p-3">
                    <div className="flex items-center justify-between">
                      <h3 className="font-semibold">{p.name}</h3>
                      {isCurrent ? <Badge>Current</Badge> : <Badge>{p.productMode}</Badge>}
                    </div>
                    <p className="mt-1 text-sm text-slate-400">{p.description}</p>
                    {latest && (
                      <p className="mt-2 text-xs text-slate-500">
                        {latest.entitlements.filter((e) => e.enabled).length} features · version {latest.version}
                      </p>
                    )}
                    {!isCurrent && latest && (
                      <div className="mt-3 flex gap-2">
                        <Button onClick={() => void upgrade(latest.id)}>Upgrade</Button>
                        <Button variant="secondary" onClick={() => void previewDowngrade(latest.id)}>Downgrade…</Button>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
            {impact && (
              <div className="mt-4 rounded border border-amber-700 bg-amber-950/40 p-3 text-sm">
                <h3 className="font-semibold">Downgrade impact preview (§115)</h3>
                <ul className="mt-2 list-disc pl-5 text-slate-300">
                  <li>Data deleted: <strong>never</strong> — downgrades never delete data.</li>
                  {impact.disabledFeatures.length > 0 && <li>Features disabled: {impact.disabledFeatures.join(", ")}</li>}
                  {impact.overLimitDimensions.map((d) => (
                    <li key={d.dimension}>{d.dimension}: current {d.currentUsage} exceeds new limit {d.newLimit} → read/export only</li>
                  ))}
                </ul>
                <div className="mt-3 flex gap-2">
                  <Button onClick={() => void confirmDowngrade()}>Acknowledge &amp; downgrade</Button>
                  <Button variant="secondary" onClick={() => { setImpact(null); setPendingVersion(null); }}>Keep current plan</Button>
                </div>
              </div>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
