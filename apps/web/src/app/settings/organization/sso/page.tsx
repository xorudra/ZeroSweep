"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { Badge, Card } from "@dsrclone/ui";
import { apiFetch } from "@/lib/api-client";

interface ProviderRow { id: string; name: string; type: string; enabled: boolean; enforceSso: boolean; jitEnabled: boolean; jitDefaultRole: string; oidc?: { issuer: string; clientId: string; clientSecretRef: string; clientSecretConfigured: boolean } | null; saml?: { idpEntityId: string; ssoUrl: string; spEntityId: string; certificateConfigured: boolean; wantEncryptedAssertions: boolean } | null }
interface Policy { mfaRequirement: string; ssoRequirement: string; passwordLoginAllowed: boolean; sessionIdleMinutes: number; sessionAbsoluteMinutes: number; patAllowed: boolean; scimEnabled: boolean; jitEnabled: boolean }
interface DomainRow { id: string; domain: string; status: string }

/**
 * Enterprise SSO administration (Prompt 23 §90). Client secrets are entered
 * as secret REFERENCES only (env:<VAR>) — a secret value typed here would
 * have nowhere safe to go, and the API never returns one. SAML signing
 * certificates are public IdP material. Enabling enforcement is refused
 * server-side without a working provider + recovery path (§100).
 */
export default function SsoSettingsPage() {
  const [orgId, setOrgId] = useState("");
  const [providers, setProviders] = useState<ProviderRow[]>([]);
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [domains, setDomains] = useState<DomainRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [oidc, setOidc] = useState({ name: "", issuer: "", clientId: "", clientSecretRef: "" });
  const [saml, setSaml] = useState({ name: "", idpEntityId: "", ssoUrl: "", spEntityId: "", certificate: "" });
  const [domain, setDomain] = useState("");
  const [dnsInfo, setDnsInfo] = useState<string | null>(null);
  const [breakGlassUser, setBreakGlassUser] = useState("");

  const load = useCallback(async () => {
    try {
      const me = await apiFetch<{ organizationId: string }>("/auth/me");
      setOrgId(me.organizationId);
      const [p, pol, d] = await Promise.all([
        apiFetch<ProviderRow[]>(`/organizations/${me.organizationId}/sso`),
        apiFetch<Policy>(`/organizations/${me.organizationId}/security-policy`),
        apiFetch<DomainRow[]>(`/organizations/${me.organizationId}/domains`),
      ]);
      setProviders(p); setPolicy(pol); setDomains(d);
    } catch (e) { setError((e as Error).message); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  const act = async (fn: () => Promise<unknown>, msg: string) => {
    setError(null);
    try { await fn(); setNotice(msg); await load(); } catch (e) { setError((e as Error).message); }
  };

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Settings" title="Single sign-on & security policy" body="OIDC and SAML providers, enforcement policy, verified domains and break-glass recovery. Unconfigured SSO honestly reports NOT_CONFIGURED — local sign-in keeps working until you enforce SSO safely." />
      {error && <p className="text-sm text-red-400">{error}</p>}
      {notice && <p className="text-sm text-emerald-400">{notice}</p>}
      <Card>
        <h2 className="font-semibold">Providers</h2>
        {providers.length === 0 && <p className="mt-2 text-sm text-slate-400">SSO status: NOT_CONFIGURED — no providers yet.</p>}
        {providers.map((p) => (
          <div key={p.id} className="mt-3 flex flex-wrap items-center gap-3 border-t border-slate-800 pt-3 text-sm">
            <span className="font-medium">{p.name}</span><Badge>{p.type}</Badge>
            <span>{p.enabled ? "Enabled" : "Disabled"}{p.enforceSso ? " · Enforced" : ""}{p.jitEnabled ? ` · JIT (${p.jitDefaultRole})` : ""}</span>
            <span className="text-slate-400">{p.type === "OIDC" ? `Issuer ${p.oidc?.issuer ?? "—"} · secret ${p.oidc?.clientSecretConfigured ? "reference resolves" : "NOT_CONFIGURED"}` : `IdP ${p.saml?.idpEntityId ?? "—"} · certificate ${p.saml?.certificateConfigured ? "present" : "missing"}`}</span>
            <button className="text-sky-300 hover:underline" onClick={() => void act(async () => { const res = await apiFetch<{ status: string; issues: string[] }>(`/organizations/${orgId}/sso/test`, { method: "POST", body: JSON.stringify({ providerId: p.id }) }); setNotice(`Test result: ${res.status}${res.issues.length ? ` — ${res.issues.join("; ")}` : ""}`); }, "")}>Test</button>
            <button className="text-sky-300 hover:underline" onClick={() => void act(() => apiFetch(`/organizations/${orgId}/sso/${p.id}`, { method: "PATCH", body: JSON.stringify({ enabled: !p.enabled }) }), "Provider updated.")}>{p.enabled ? "Disable" : "Enable"}</button>
            <button className="text-sky-300 hover:underline" onClick={() => void act(() => apiFetch(`/organizations/${orgId}/sso/${p.id}`, { method: "PATCH", body: JSON.stringify({ enforceSso: !p.enforceSso }) }), "Enforcement updated.")}>{p.enforceSso ? "Stop enforcing" : "Enforce SSO"}</button>
          </div>
        ))}
        <div className="mt-4 grid gap-3 md:grid-cols-2">
          <div className="rounded bg-slate-900 p-3">
            <h3 className="text-sm font-semibold">Add OIDC provider</h3>
            <input className="mt-2 w-full rounded bg-slate-950 px-2 py-1 text-sm" placeholder="Display name" value={oidc.name} onChange={(e) => setOidc({ ...oidc, name: e.target.value })} />
            <input className="mt-2 w-full rounded bg-slate-950 px-2 py-1 text-sm" placeholder="Issuer URL (https://idp.example.com)" value={oidc.issuer} onChange={(e) => setOidc({ ...oidc, issuer: e.target.value })} />
            <input className="mt-2 w-full rounded bg-slate-950 px-2 py-1 text-sm" placeholder="Client ID" value={oidc.clientId} onChange={(e) => setOidc({ ...oidc, clientId: e.target.value })} />
            <input className="mt-2 w-full rounded bg-slate-950 px-2 py-1 text-sm" placeholder="Client secret REFERENCE (env:OIDC_CLIENT_SECRET)" value={oidc.clientSecretRef} onChange={(e) => setOidc({ ...oidc, clientSecretRef: e.target.value })} />
            <button className="mt-3 rounded bg-sky-600 px-3 py-1 text-sm" onClick={() => void act(() => apiFetch(`/organizations/${orgId}/sso`, { method: "POST", body: JSON.stringify({ type: "OIDC", ...oidc }) }), "OIDC provider saved (disabled until tested).")}>Save OIDC provider</button>
          </div>
          <div className="rounded bg-slate-900 p-3">
            <h3 className="text-sm font-semibold">Add SAML provider</h3>
            <input className="mt-2 w-full rounded bg-slate-950 px-2 py-1 text-sm" placeholder="Display name" value={saml.name} onChange={(e) => setSaml({ ...saml, name: e.target.value })} />
            <input className="mt-2 w-full rounded bg-slate-950 px-2 py-1 text-sm" placeholder="IdP entity ID" value={saml.idpEntityId} onChange={(e) => setSaml({ ...saml, idpEntityId: e.target.value })} />
            <input className="mt-2 w-full rounded bg-slate-950 px-2 py-1 text-sm" placeholder="IdP SSO URL" value={saml.ssoUrl} onChange={(e) => setSaml({ ...saml, ssoUrl: e.target.value })} />
            <input className="mt-2 w-full rounded bg-slate-950 px-2 py-1 text-sm" placeholder="SP entity ID" value={saml.spEntityId} onChange={(e) => setSaml({ ...saml, spEntityId: e.target.value })} />
            <textarea className="mt-2 w-full rounded bg-slate-950 px-2 py-1 text-sm" placeholder="IdP signing certificate (PEM, public material)" rows={3} value={saml.certificate} onChange={(e) => setSaml({ ...saml, certificate: e.target.value })} />
            <button className="mt-3 rounded bg-sky-600 px-3 py-1 text-sm" onClick={() => void act(() => apiFetch(`/organizations/${orgId}/sso`, { method: "POST", body: JSON.stringify({ type: "SAML", ...saml }) }), "SAML provider saved (disabled until tested).")}>Save SAML provider</button>
          </div>
        </div>
      </Card>
      {policy && (
        <Card>
          <h2 className="font-semibold">Security policy</h2>
          <div className="mt-3 grid gap-3 text-sm md:grid-cols-3">
            <label>MFA requirement
              <select className="mt-1 w-full rounded bg-slate-900 px-2 py-1" value={policy.mfaRequirement} onChange={(e) => setPolicy({ ...policy, mfaRequirement: e.target.value })}>
                <option>OPTIONAL</option><option>REQUIRED_FOR_ADMINS</option><option>REQUIRED_FOR_ALL</option>
              </select></label>
            <label>SSO requirement
              <select className="mt-1 w-full rounded bg-slate-900 px-2 py-1" value={policy.ssoRequirement} onChange={(e) => setPolicy({ ...policy, ssoRequirement: e.target.value })}>
                <option>OPTIONAL</option><option>SSO_REQUIRED</option>
              </select></label>
            <label>Session idle (minutes)<input type="number" className="mt-1 w-full rounded bg-slate-900 px-2 py-1" value={policy.sessionIdleMinutes} onChange={(e) => setPolicy({ ...policy, sessionIdleMinutes: Number(e.target.value) })} /></label>
            <label>Session absolute (minutes)<input type="number" className="mt-1 w-full rounded bg-slate-900 px-2 py-1" value={policy.sessionAbsoluteMinutes} onChange={(e) => setPolicy({ ...policy, sessionAbsoluteMinutes: Number(e.target.value) })} /></label>
            <label className="flex items-center gap-2"><input type="checkbox" checked={policy.patAllowed} onChange={(e) => setPolicy({ ...policy, patAllowed: e.target.checked })} /> Personal API tokens allowed</label>
            <label className="flex items-center gap-2"><input type="checkbox" checked={policy.scimEnabled} onChange={(e) => setPolicy({ ...policy, scimEnabled: e.target.checked })} /> SCIM provisioning enabled</label>
          </div>
          <button className="mt-3 rounded bg-sky-600 px-4 py-2 text-sm" onClick={() => void act(() => apiFetch(`/organizations/${orgId}/security-policy`, { method: "PATCH", body: JSON.stringify(policy) }), "Policy saved — enforced by the API services, not just this page.")}>Save policy</button>
          <p className="mt-2 text-xs text-slate-500">Unsafe combinations are refused: SSO cannot be required without an enabled provider and a recovery path (§100).</p>
        </Card>
      )}
      <Card>
        <h2 className="font-semibold">Verified domains & break-glass</h2>
        <div className="mt-2 space-y-1 text-sm">{domains.map((d) => <p key={d.id}>{d.domain} — <Badge>{d.status}</Badge></p>)}{domains.length === 0 && <p className="text-slate-400">No domains registered.</p>}</div>
        <div className="mt-3 flex flex-wrap gap-2">
          <input className="rounded bg-slate-900 px-3 py-2 text-sm" placeholder="example.com" value={domain} onChange={(e) => setDomain(e.target.value)} />
          <button className="rounded bg-sky-600 px-4 py-2 text-sm" onClick={() => void act(async () => { const res = await apiFetch<{ dnsRecord: { name: string; value: string } }>(`/organizations/${orgId}/domains`, { method: "POST", body: JSON.stringify({ domain }) }); setDnsInfo(`Publish TXT ${res.dnsRecord.name} → ${res.dnsRecord.value} (token shown once; only its hash is stored)`); }, "Domain registered — publish the TXT record, then verify from the API.")}>Start verification</button>
        </div>
        {dnsInfo && <p className="mt-2 break-all text-xs text-amber-300">{dnsInfo}</p>}
        <div className="mt-4 flex flex-wrap gap-2">
          <input className="rounded bg-slate-900 px-3 py-2 text-sm" placeholder="Break-glass admin user ID" value={breakGlassUser} onChange={(e) => setBreakGlassUser(e.target.value)} />
          <button className="rounded bg-amber-600 px-4 py-2 text-sm" onClick={() => void act(() => apiFetch(`/organizations/${orgId}/break-glass`, { method: "POST", body: JSON.stringify({ userId: breakGlassUser }) }), "Break-glass admin enrolled. Their password logins remain possible under SSO enforcement and are always audited + alerted.")}>Enroll break-glass admin</button>
        </div>
      </Card>
    </div>
  );
}
