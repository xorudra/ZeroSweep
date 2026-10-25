"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { Badge, Card } from "@zerosweep/ui";
import { apiFetch } from "@/lib/api-client";

interface AccountRow { id: string; name: string; status: string; workspaceId: string | null; scopes: string[]; lastUsedAt: string | null }
const SCOPES = ["findings:read", "assets:read", "scans:read", "scans:create-safe", "reports:read", "reports:create", "targets:read", "vulnerabilities:read", "notifications:read"];

/**
 * Service accounts (Prompt 23 §105). Non-human identities for CI and
 * integrations: least-privilege scopes, optionally bound to ONE workspace,
 * never interactive login, never inheriting user permissions.
 */
export default function ServiceAccountsPage() {
  const [accounts, setAccounts] = useState<AccountRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [plaintext, setPlaintext] = useState<string | null>(null);
  const [form, setForm] = useState<{ name: string; scopes: string[]; workspaceId: string }>({ name: "", scopes: ["reports:create"], workspaceId: "" });

  const load = useCallback(async () => {
    try { setAccounts(await apiFetch<AccountRow[]>("/service-accounts")); } catch (e) { setError((e as Error).message); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  const act = async (fn: () => Promise<unknown>, msg: string) => {
    setError(null);
    try { await fn(); setNotice(msg); await load(); } catch (e) { setError((e as Error).message); }
  };
  const toggleScope = (scope: string) => setForm({ ...form, scopes: form.scopes.includes(scope) ? form.scopes.filter((s) => s !== scope) : [...form.scopes, scope] });

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Settings" title="Service accounts" body="Machine identities for automation. Credentials are separate API keys bound to the account's scopes; disabling the account denies its keys immediately." />
      {error && <p className="text-sm text-red-400">{error}</p>}
      {notice && <p className="text-sm text-emerald-400">{notice}</p>}
      <Card>
        <h2 className="font-semibold">Accounts</h2>
        {accounts.map((a) => (
          <div key={a.id} className="mt-2 flex flex-wrap items-center gap-3 text-sm">
            <span className="font-medium">{a.name}</span><Badge>{a.status}</Badge>
            <span className="text-slate-400">{a.workspaceId ? `workspace ${a.workspaceId}` : "organization-wide"}</span>
            <span className="text-slate-400">{a.scopes.join(", ")}</span>
            {a.status === "ACTIVE" && <>
              <button className="text-sky-300 hover:underline" onClick={() => void act(async () => { const res = await apiFetch<{ plaintext: string }>(`/service-accounts/${a.id}/credentials`, { method: "POST", body: JSON.stringify({ name: `${a.name} key` }) }); setPlaintext(res.plaintext); }, "Credential minted (shown once).")}>Mint credential</button>
              <button className="text-red-300 hover:underline" onClick={() => void act(() => apiFetch(`/service-accounts/${a.id}`, { method: "DELETE" }), "Service account disabled.")}>Disable</button>
            </>}
          </div>
        ))}
        {accounts.length === 0 && <p className="mt-2 text-sm text-slate-400">No service accounts yet.</p>}
        {plaintext && <p className="mt-3 break-all rounded bg-slate-900 p-3 text-xs text-amber-300">Credential (shown once): {plaintext}</p>}
      </Card>
      <Card>
        <h2 className="font-semibold">Create service account</h2>
        <div className="mt-2 flex flex-wrap gap-2">
          <input className="rounded bg-slate-900 px-3 py-2 text-sm" placeholder="Name (e.g. github-actions)" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
          <input className="rounded bg-slate-900 px-3 py-2 text-sm" placeholder="Workspace ID (optional)" value={form.workspaceId} onChange={(e) => setForm({ ...form, workspaceId: e.target.value })} />
        </div>
        <div className="mt-3 flex flex-wrap gap-3 text-sm">
          {SCOPES.map((s) => <label key={s} className="flex items-center gap-1"><input type="checkbox" checked={form.scopes.includes(s)} onChange={() => toggleScope(s)} />{s}</label>)}
        </div>
        <button className="mt-3 rounded bg-sky-600 px-4 py-2 text-sm" onClick={() => void act(() => apiFetch("/service-accounts", { method: "POST", body: JSON.stringify({ name: form.name, scopes: form.scopes, workspaceId: form.workspaceId || undefined }) }), "Service account created.")}>Create account</button>
      </Card>
    </div>
  );
}
