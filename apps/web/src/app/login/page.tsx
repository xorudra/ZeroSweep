"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { api, ApiError, setToken } from "@/lib/api-client";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setError(null);
    try {
      const res = await api.login(email, password);
      setToken(res.accessToken);
      router.replace("/");
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Login failed. Is the API running?");
    } finally { setBusy(false); }
  }

  return (
    <main className="flex min-h-screen items-center justify-center bg-slate-950 p-5">
      <form onSubmit={onSubmit} className="w-full max-w-sm rounded-2xl border border-slate-800 bg-slate-900/60 p-6">
        <p className="font-mono text-[11px] uppercase tracking-widest text-cyan-400">Authorized VAPT Platform</p>
        <h1 className="mt-1 text-2xl font-bold text-slate-50">Sign in to DSRclone</h1>
        <label className="mt-5 block text-sm text-slate-300">Email
          <input required type="email" value={email} onChange={(e) => setEmail(e.target.value)}
            className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100" />
        </label>
        <label className="mt-3 block text-sm text-slate-300">Password
          <input required type="password" value={password} onChange={(e) => setPassword(e.target.value)}
            className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 text-slate-100" />
        </label>
        {error ? <p className="mt-3 text-sm text-red-300">{error}</p> : null}
        <button disabled={busy} className="mt-5 w-full rounded-lg bg-cyan-500 px-4 py-2 font-semibold text-slate-950 hover:bg-cyan-400 disabled:opacity-60" type="submit">
          {busy ? "Signing in…" : "Sign in"}
        </button>
        <p className="mt-3 text-xs text-slate-500">Accounts are created via the API registration endpoint. Access is organization-scoped with role-based permissions.</p>
      </form>
    </main>
  );
}
