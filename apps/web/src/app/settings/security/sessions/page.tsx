"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { Badge, Card } from "@zerosweep/ui";
import { apiFetch } from "@/lib/api-client";

interface SessionRow { id: string; createdAt: string; expiresAt: string; assurance: string; revokedAt: string | null; current: boolean }

/**
 * My sessions & password (Prompt 23 §93). Sessions are server-side records
 * with idle + absolute lifetimes from organization policy; revoking here
 * ends access immediately, including for stolen tokens.
 */
export default function SessionsSettingsPage() {
  const [sessions, setSessions] = useState<SessionRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [pw, setPw] = useState({ currentPassword: "", newPassword: "" });

  const load = useCallback(async () => {
    try { setSessions(await apiFetch<SessionRow[]>("/auth/sessions")); } catch (e) { setError((e as Error).message); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  const act = async (fn: () => Promise<unknown>, msg: string) => {
    setError(null);
    try { await fn(); setNotice(msg); await load(); } catch (e) { setError((e as Error).message); }
  };

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Settings" title="Sessions & password" body="Your active device sessions and local password. Password changes revoke your other sessions." />
      {error && <p className="text-sm text-red-400">{error}</p>}
      {notice && <p className="text-sm text-emerald-400">{notice}</p>}
      <Card>
        <h2 className="font-semibold">Active sessions</h2>
        {sessions.map((s) => (
          <div key={s.id} className="mt-2 flex items-center gap-3 text-sm">
            <span>{new Date(s.createdAt).toLocaleString()}</span><Badge>{s.assurance}</Badge>
            <span className="text-slate-400">expires {new Date(s.expiresAt).toLocaleString()}</span>
            {s.current && <Badge>THIS DEVICE</Badge>}
            {!s.current && <button className="text-red-300 hover:underline" onClick={() => void act(() => apiFetch(`/auth/sessions/${s.id}`, { method: "DELETE" }), "Session revoked.")}>Revoke</button>}
          </div>
        ))}
        {sessions.length === 0 && <p className="mt-2 text-sm text-slate-400">No server-side sessions recorded for this sign-in.</p>}
        <button className="mt-3 rounded bg-red-700 px-4 py-2 text-sm" onClick={() => void act(() => apiFetch("/auth/sessions", { method: "DELETE" }), "All sessions revoked.")}>Revoke all sessions</button>
      </Card>
      <Card>
        <h2 className="font-semibold">Change password</h2>
        <div className="mt-3 flex flex-wrap gap-2">
          <input type="password" className="rounded bg-slate-900 px-3 py-2 text-sm" placeholder="Current password" value={pw.currentPassword} onChange={(e) => setPw({ ...pw, currentPassword: e.target.value })} />
          <input type="password" className="rounded bg-slate-900 px-3 py-2 text-sm" placeholder="New password (policy-checked)" value={pw.newPassword} onChange={(e) => setPw({ ...pw, newPassword: e.target.value })} />
          <button className="rounded bg-sky-600 px-4 py-2 text-sm" onClick={() => void act(() => apiFetch("/auth/password/change", { method: "POST", body: JSON.stringify(pw) }), "Password changed — other sessions revoked, event audited.")}>Change password</button>
        </div>
      </Card>
    </div>
  );
}
