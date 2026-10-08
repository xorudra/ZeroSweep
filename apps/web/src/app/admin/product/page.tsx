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
 * Platform product control plane (Prompt 40 §95–§106): organizations,
 * subscriptions, licenses, usage, trials, features, plans, release and
 * support access for PLATFORM administrators. Every view is metadata
 * only — passwords, secrets and customer content are never shown
 * (§104–§106). Tenant admins do not get this surface.
 */
interface Org { id: string; name: string; slug: string; lifecycleStatus: string; isDemo: boolean; createdAt: string; plan: { code: string; status: string } | null }
interface Sub { id: string; organizationId: string; status: string; planVersion: { plan: { code: string } } }
interface Trial { id: string; organizationId: string; status: string; expiresAt: string }
interface License { id: string; licenseId: string; edition: string; organizationId: string | null; expiresAt: string; revokedAt: string | null }
interface Feature { key: string; name: string; category: string; safetyInvariant: boolean }
interface Release { version: string; productMode: string; billing: { status: string }; licensingEnabled: boolean }
interface Support { id: string; organizationId: string; reason: string; status: string; tenantApproved: boolean; expiresAt: string }

export default function Page() {
  const [orgs, setOrgs] = useState<Org[]>([]);
  const [subs, setSubs] = useState<Sub[]>([]);
  const [trials, setTrials] = useState<Trial[]>([]);
  const [licenses, setLicenses] = useState<License[]>([]);
  const [features, setFeatures] = useState<Feature[]>([]);
  const [release, setRelease] = useState<Release | null>(null);
  const [support, setSupport] = useState<Support[]>([]);
  const [usageItems, setUsageItems] = useState<Array<{ organizationId: string; metric: string; quantity: number }>>([]);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const load = useCallback(async () => {
    try {
      const [o, s, t, l, f, r, sup, u] = await Promise.all([
        apiFetch<{ items: Org[] }>("/platform/organizations"),
        apiFetch<{ items: Sub[] }>("/platform/subscriptions"),
        apiFetch<{ items: Trial[] }>("/platform/trials"),
        apiFetch<{ items: License[] }>("/platform/licenses"),
        apiFetch<{ items: Feature[] }>("/platform/features"),
        apiFetch<Release>("/platform/release"),
        apiFetch<{ items: Support[] }>("/platform/support-access"),
        apiFetch<{ items: Array<{ organizationId: string; metric: string; quantity: number }> }>("/platform/usage"),
      ]);
      setOrgs(o.items ?? []); setSubs(s.items ?? []); setTrials(t.items ?? []);
      setLicenses(l.items ?? []); setFeatures(f.items ?? []); setRelease(r);
      setSupport(sup.items ?? []); setUsageItems(u.items ?? []);
    } catch (e) {
      setError(e instanceof ApiError ? e.message : "Could not reach the API. Platform product administration requires the platform administrator flag (§98).");
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  async function act(path: string, body: Record<string, unknown> = {}) {
    setError(""); setNotice("");
    try {
      await apiFetch(path, { method: "POST", body: JSON.stringify(body) });
      setNotice("Done.");
      await load();
    } catch (e) { setError(e instanceof ApiError ? e.message : "Action failed."); }
  }

  return (
    <div className="space-y-6 p-6">
      <PageHeader eyebrow="Platform Control" title="Product Administration" body="Plans, subscriptions, licenses, trials, usage and support access across organizations — metadata only. Support access is reason-bound, tenant-approved, expiring and fully audited (§100–§103); there is no silent impersonation." />
      {error && <Card><p className="text-sm text-red-300">{error}</p></Card>}
      {notice && <Card><p className="text-sm text-emerald-300">{notice}</p></Card>}
      {release && (
        <Card>
          <div className="flex flex-wrap items-center gap-3">
            <h2 className="text-base font-semibold">Release {release.version}</h2>
            <Badge>{release.productMode}</Badge>
            <Badge>Billing: {release.billing.status}</Badge>
            <Badge>Licensing: {release.licensingEnabled ? "enabled" : "not configured"}</Badge>
          </div>
        </Card>
      )}
      <Card>
        <h2 className="mb-3 text-base font-semibold">Organizations</h2>
        {orgs.length === 0 ? <EmptyState title="No organizations" body="No organizations exist yet, or you lack platform access." /> : (
          <table className="w-full text-sm">
            <thead><tr className="text-left text-slate-400"><th className="py-1">Organization</th><th>Plan</th><th>Lifecycle</th><th>Created</th><th></th></tr></thead>
            <tbody>
              {orgs.map((o) => (
                <tr key={o.id} className="border-t border-slate-800">
                  <td className="py-1">{o.name} <span className="text-slate-500">({o.slug})</span>{o.isDemo && <Badge> DEMO</Badge>}</td>
                  <td>{o.plan ? `${o.plan.code} · ${o.plan.status}` : "—"}</td>
                  <td>{o.lifecycleStatus}</td>
                  <td>{new Date(o.createdAt).toLocaleDateString()}</td>
                  <td className="space-x-2">
                    {o.lifecycleStatus === "ACTIVE" && <Button variant="secondary" onClick={() => void act(`/platform/organizations/${o.id}/suspend`)}>Suspend</Button>}
                    {o.lifecycleStatus === "SUSPENDED" && <Button variant="secondary" onClick={() => void act(`/platform/organizations/${o.id}/reactivate`)}>Reactivate</Button>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <h2 className="mb-3 text-base font-semibold">Subscriptions</h2>
          {subs.length === 0 ? <EmptyState title="No subscriptions" body="None recorded." /> : (
            <ul className="space-y-1 text-sm">
              {subs.map((s) => <li key={s.id} className="flex justify-between border-t border-slate-800 py-1"><span>{s.planVersion.plan.code}</span><span className="text-slate-400">{s.status} · {s.organizationId.slice(0, 8)}…</span></li>)}
            </ul>
          )}
        </Card>
        <Card>
          <div className="mb-3 flex items-center justify-between">
            <h2 className="text-base font-semibold">Trials</h2>
            <Button variant="secondary" onClick={() => void act("/platform/trials/expire")}>Run expiry sweep</Button>
          </div>
          {trials.length === 0 ? <EmptyState title="No trials" body="None recorded." /> : (
            <ul className="space-y-1 text-sm">
              {trials.map((t) => <li key={t.id} className="flex justify-between border-t border-slate-800 py-1"><span>{t.organizationId.slice(0, 8)}…</span><span className="text-slate-400">{t.status} · ends {new Date(t.expiresAt).toLocaleDateString()}</span></li>)}
            </ul>
          )}
        </Card>
        <Card>
          <h2 className="mb-3 text-base font-semibold">Licenses</h2>
          {licenses.length === 0 ? <EmptyState title="No licenses" body="No product licenses installed." /> : (
            <ul className="space-y-1 text-sm">
              {licenses.map((l) => <li key={l.id} className="flex justify-between border-t border-slate-800 py-1"><span>{l.licenseId} · {l.edition}</span><span className="text-slate-400">{l.revokedAt ? "REVOKED" : `expires ${new Date(l.expiresAt).toLocaleDateString()}`}</span></li>)}
            </ul>
          )}
        </Card>
        <Card>
          <h2 className="mb-3 text-base font-semibold">Usage totals (billing period)</h2>
          {usageItems.length === 0 ? <EmptyState title="No usage aggregates" body="No billing-period aggregates yet." /> : (
            <ul className="space-y-1 text-sm">
              {usageItems.slice(0, 20).map((u, i) => <li key={i} className="flex justify-between border-t border-slate-800 py-1"><span>{u.metric}</span><span className="text-slate-400">{u.quantity.toLocaleString()} · {u.organizationId.slice(0, 8)}…</span></li>)}
            </ul>
          )}
        </Card>
      </div>
      <Card>
        <h2 className="mb-3 text-base font-semibold">Support access sessions</h2>
        {support.length === 0 ? <EmptyState title="No support sessions" body="No support access sessions exist. Sessions require a reason, tenant approval and an expiry, and are audited (§100–§103)." /> : (
          <ul className="space-y-1 text-sm">
            {support.map((s) => (
              <li key={s.id} className="flex items-center justify-between border-t border-slate-800 py-1">
                <span>{s.reason}</span>
                <span className="flex items-center gap-2 text-slate-400">
                  <Badge>{s.status}</Badge> tenant approved: {s.tenantApproved ? "yes" : "no"} · expires {new Date(s.expiresAt).toLocaleString()}
                  {s.status === "ACTIVE" && <Button variant="secondary" onClick={() => void act(`/platform/support-access/${s.id}/end`)}>End</Button>}
                </span>
              </li>
            ))}
          </ul>
        )}
      </Card>
      <Card>
        <h2 className="mb-3 text-base font-semibold">Feature registry</h2>
        <div className="grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {features.map((f) => (
            <div key={f.key} className="rounded border border-slate-800 px-3 py-2 text-sm">
              <div className="font-medium">{f.name}</div>
              <div className="text-xs text-slate-500">{f.key} · {f.category}{f.safetyInvariant ? " · safety invariant (never entitlement-gated, §16)" : ""}</div>
            </div>
          ))}
        </div>
      </Card>
    </div>
  );
}
