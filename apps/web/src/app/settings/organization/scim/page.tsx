"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { Card } from "@zerosweep/ui";
import { apiFetch } from "@/lib/api-client";

interface TokenStatus { configured: boolean; prefix?: string; createdAt?: string; rotatedAt?: string; lastUsedAt?: string }
interface Mapping { id: string; externalGroup: string; organizationRole: string; workspaceId: string | null; workspaceRole: string | null }
const ROLES = ["VIEWER", "MEMBER", "ANALYST", "SECURITY_ENGINEER", "SECURITY_ADMIN", "ADMIN"];

/**
 * SCIM administration (Prompt 23 §91). The bearer token is shown exactly
 * once (only its hash + prefix persist). Group → role mappings are the ONLY
 * way provisioned groups gain roles — an unmapped IdP group grants nothing
 * beyond the default viewer (§71/§131).
 */
export default function ScimSettingsPage() {
  const [orgId, setOrgId] = useState("");
  const [status, setStatus] = useState<TokenStatus | null>(null);
  const [mappings, setMappings] = useState<Mapping[]>([]);
  const [token, setToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [form, setForm] = useState({ externalGroup: "", organizationRole: "VIEWER" });

  const load = useCallback(async () => {
    try {
      const me = await apiFetch<{ organizationId: string }>("/auth/me");
      setOrgId(me.organizationId);
      const [s, m] = await Promise.all([
        apiFetch<TokenStatus>(`/organizations/${me.organizationId}/scim`),
        apiFetch<Mapping[]>(`/organizations/${me.organizationId}/scim/mappings`),
      ]);
      setStatus(s); setMappings(m);
    } catch (e) { setError((e as Error).message); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Settings" title="SCIM provisioning" body="IdP-driven user and group lifecycle at /scim/v2. Deprovisioning disables accounts and revokes sessions — records are never deleted." />
      {error && <p className="text-sm text-red-400">{error}</p>}
      {notice && <p className="text-sm text-emerald-400">{notice}</p>}
      <Card>
        <h2 className="font-semibold">Bearer token</h2>
        <p className="mt-1 text-sm text-slate-400">{status?.configured ? `Configured · prefix ${status.prefix} · last used ${status.lastUsedAt ?? "never"}` : "Not configured — SCIM endpoints reject all calls until a token exists."}</p>
        <button className="mt-3 rounded bg-sky-600 px-4 py-2 text-sm" onClick={async () => { setError(null); try { const res = await apiFetch<{ token: string }>(`/organizations/${orgId}/scim/token`, { method: "POST" }); setToken(res.token); setNotice(status?.configured ? "Token rotated — the old token stops working immediately." : "Token created."); await load(); } catch (e) { setError((e as Error).message); } }}>{status?.configured ? "Rotate token" : "Create token"}</button>
        {token && <p className="mt-3 break-all rounded bg-slate-900 p-3 text-xs text-amber-300">SCIM token (shown once): {token}</p>}
      </Card>
      <Card>
        <h2 className="font-semibold">Group → role mappings</h2>
        {mappings.map((m) => <p key={m.id} className="mt-2 text-sm">{m.externalGroup} → organization role <b>{m.organizationRole}</b>{m.workspaceId ? ` · workspace ${m.workspaceId} as ${m.workspaceRole}` : ""}</p>)}
        {mappings.length === 0 && <p className="mt-2 text-sm text-slate-400">No mappings — provisioned users receive the default VIEWER role only.</p>}
        <div className="mt-3 flex flex-wrap gap-2">
          <input className="rounded bg-slate-900 px-3 py-2 text-sm" placeholder="IdP group name" value={form.externalGroup} onChange={(e) => setForm({ ...form, externalGroup: e.target.value })} />
          <select className="rounded bg-slate-900 px-2 py-2 text-sm" value={form.organizationRole} onChange={(e) => setForm({ ...form, organizationRole: e.target.value })}>{ROLES.map((r) => <option key={r} value={r}>{r}</option>)}</select>
          <button className="rounded bg-sky-600 px-4 py-2 text-sm" onClick={async () => { setError(null); try { await apiFetch(`/organizations/${orgId}/scim/mappings`, { method: "POST", body: JSON.stringify(form) }); setNotice("Mapping saved (administrator approval recorded in the audit log)."); await load(); } catch (e) { setError((e as Error).message); } }}>Add mapping</button>
        </div>
      </Card>
    </div>
  );
}
