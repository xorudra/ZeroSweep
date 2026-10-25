"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { Badge, Card } from "@zerosweep/ui";
import { apiFetch } from "@/lib/api-client";

interface KeyRow { id: string; name: string; prefix: string; ownerKind: string; scopes: string[]; expiresAt: string | null; lastUsedAt: string | null; revokedAt: string | null }
const SCOPES = ["findings:read", "assets:read", "scans:read", "scans:create-safe", "reports:read", "reports:create", "targets:read", "vulnerabilities:read", "notifications:read"];

/**
 * API keys (Prompt 23). Keys are high-entropy and shown exactly once — the
 * server stores only a prefix + hash. Scopes come from a closed typed
 * catalog: there is no way to request shell, tool-execution or
 * approval-bypass authority because such scopes do not exist (§79).
 */
export default function ApiKeysPage() {
  const [keys, setKeys] = useState<KeyRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [plaintext, setPlaintext] = useState<string | null>(null);
  const [form, setForm] = useState<{ name: string; scopes: string[] }>({ name: "", scopes: ["findings:read"] });

  const load = useCallback(async () => {
    try { setKeys(await apiFetch<KeyRow[]>("/api-keys")); } catch (e) { setError((e as Error).message); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  const act = async (fn: () => Promise<unknown>, msg: string) => {
    setError(null);
    try { await fn(); setNotice(msg); await load(); } catch (e) { setError((e as Error).message); }
  };
  const toggleScope = (scope: string) => setForm({ ...form, scopes: form.scopes.includes(scope) ? form.scopes.filter((s) => s !== scope) : [...form.scopes, scope] });

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Settings" title="API keys" body="Personal access tokens with typed, least-privilege scopes. Organization policy can disable PATs entirely; maximum lifetimes are policy-capped." />
      {error && <p className="text-sm text-red-400">{error}</p>}
      {notice && <p className="text-sm text-emerald-400">{notice}</p>}
      <Card>
        <h2 className="font-semibold">Your keys</h2>
        {keys.map((k) => (
          <div key={k.id} className="mt-2 flex flex-wrap items-center gap-3 text-sm">
            <span className="font-medium">{k.name}</span><span className="text-slate-400">{k.prefix}…</span><Badge>{k.ownerKind}</Badge>
            <span className="text-slate-400">{k.scopes.join(", ")}</span>
            <span className="text-slate-400">{k.revokedAt ? "Revoked" : `Last used ${k.lastUsedAt ?? "never"}`}</span>
            {!k.revokedAt && <>
              <button className="text-sky-300 hover:underline" onClick={() => void act(async () => { const res = await apiFetch<{ plaintext: string }>("/api-keys/" + k.id + "/rotate", { method: "POST" }); setPlaintext(res.plaintext); }, "Key rotated — old key revoked.")}>Rotate</button>
              <button className="text-red-300 hover:underline" onClick={() => void act(() => apiFetch("/api-keys/" + k.id, { method: "DELETE" }), "Key revoked — reuse is denied immediately.")}>Revoke</button>
            </>}
          </div>
        ))}
        {keys.length === 0 && <p className="mt-2 text-sm text-slate-400">No API keys yet.</p>}
        {plaintext && <p className="mt-3 break-all rounded bg-slate-900 p-3 text-xs text-amber-300">New key (shown once): {plaintext}</p>}
      </Card>
      <Card>
        <h2 className="font-semibold">Create a key</h2>
        <input className="mt-2 rounded bg-slate-900 px-3 py-2 text-sm" placeholder="Key name (e.g. CI reporter)" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
        <div className="mt-3 flex flex-wrap gap-3 text-sm">
          {SCOPES.map((s) => <label key={s} className="flex items-center gap-1"><input type="checkbox" checked={form.scopes.includes(s)} onChange={() => toggleScope(s)} />{s}</label>)}
        </div>
        <button className="mt-3 rounded bg-sky-600 px-4 py-2 text-sm" onClick={() => void act(async () => { const res = await apiFetch<{ plaintext: string }>("/api-keys", { method: "POST", body: JSON.stringify(form) }); setPlaintext(res.plaintext); }, "Key created — copy it now, it cannot be shown again.")}>Create key</button>
      </Card>
    </div>
  );
}
