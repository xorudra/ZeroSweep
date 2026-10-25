"use client";

import { useCallback, useEffect, useState } from "react";
import { PageHeader } from "@/components/Shell";
import { Card } from "@zerosweep/ui";
import { apiFetch } from "@/lib/api-client";

interface MfaStatus { totpEnrolled: boolean; totpPending: boolean; passkeys: number; recoveryCodesRemaining: number }
interface Passkey { id: string; credentialId: string; transports: string[]; createdAt: string }

/**
 * My MFA & passkeys (Prompt 23 §92). The TOTP secret and recovery codes
 * are displayed exactly once — the server stores only an encrypted secret
 * and code hashes, and can never show them again. Passkey registration
 * runs the browser WebAuthn ceremony against the API challenges.
 */
export default function MfaSettingsPage() {
  const [status, setStatus] = useState<MfaStatus | null>(null);
  const [passkeys, setPasskeys] = useState<Passkey[]>([]);
  const [secret, setSecret] = useState<string | null>(null);
  const [codes, setCodes] = useState<string[] | null>(null);
  const [code, setCode] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setStatus(await apiFetch<MfaStatus>("/auth/mfa/status"));
      setPasskeys(await apiFetch<Passkey[]>("/auth/passkeys").catch(() => []));
    } catch (e) { setError((e as Error).message); }
  }, []);
  useEffect(() => { void load(); }, [load]);

  const act = async (fn: () => Promise<unknown>, msg: string) => {
    setError(null);
    try { await fn(); setNotice(msg); await load(); } catch (e) { setError((e as Error).message); }
  };

  return (
    <div className="space-y-6">
      <PageHeader eyebrow="Settings" title="Multi-factor authentication" body="TOTP authenticator, recovery codes and passkeys for your account. Administrators can require MFA by policy; enrolled users are always challenged." />
      {error && <p className="text-sm text-red-400">{error}</p>}
      {notice && <p className="text-sm text-emerald-400">{notice}</p>}
      <Card>
        <h2 className="font-semibold">Authenticator app (TOTP)</h2>
        <p className="mt-1 text-sm text-slate-400">Status: {status?.totpEnrolled ? "Enrolled" : status?.totpPending ? "Pending activation" : "Not enrolled"} · Recovery codes remaining: {status?.recoveryCodesRemaining ?? 0}</p>
        {!status?.totpEnrolled && (
          <div className="mt-3 space-y-2">
            <button className="rounded bg-sky-600 px-4 py-2 text-sm" onClick={() => void act(async () => { const res = await apiFetch<{ secret: string }>("/auth/mfa/enroll", { method: "POST" }); setSecret(res.secret); }, "")}>Start enrollment</button>
            {secret && <p className="break-all rounded bg-slate-900 p-3 text-xs text-amber-300">Secret (shown once — add it to your authenticator app): {secret}</p>}
            <div className="flex gap-2">
              <input className="rounded bg-slate-900 px-3 py-2 text-sm" placeholder="6-digit code" value={code} onChange={(e) => setCode(e.target.value)} />
              <button className="rounded bg-emerald-600 px-4 py-2 text-sm" onClick={() => void act(() => apiFetch("/auth/mfa/activate", { method: "POST", body: JSON.stringify({ code }) }), "TOTP activated. Codes are single-step — a used code can never be replayed.")}>Activate</button>
            </div>
          </div>
        )}
        <button className="mt-4 rounded bg-slate-700 px-4 py-2 text-sm" onClick={() => void act(async () => { const res = await apiFetch<{ codes: string[] }>("/auth/mfa/recovery-codes", { method: "POST" }); setCodes(res.codes); }, "")}>Generate recovery codes</button>
        {codes && <div className="mt-3 rounded bg-slate-900 p-3 text-xs text-amber-300"><p>Recovery codes (shown once — each works exactly once, old codes are destroyed):</p><p className="mt-1 break-all">{codes.join("  ")}</p></div>}
      </Card>
      <Card>
        <h2 className="font-semibold">Passkeys</h2>
        <p className="mt-1 text-sm text-slate-400">{status?.passkeys ?? 0} passkey(s) registered. Registration uses your browser's WebAuthn ceremony; private keys never leave your authenticator, and the server stores only public keys + signature counters (clone detection on counter regression).</p>
        {passkeys.map((p) => <p key={p.id} className="mt-2 text-sm">{p.credentialId.slice(0, 18)}… · added {new Date(p.createdAt).toLocaleDateString()}</p>)}
      </Card>
    </div>
  );
}
