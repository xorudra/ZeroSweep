"use client";

import Link from "next/link";
import { Suspense, useState } from "react";
import { useSearchParams } from "next/navigation";
import { apiFetch, ApiError } from "@/lib/api-client";

/**
 * Invitation acceptance — the ONLY way a new account is created on this
 * deployment (public sign-up is closed; REGISTRATION_MODE=invite-only).
 * An organization admin creates an invitation in Settings → Organization
 * → Members and shares the one-time token; the invitee sets their name
 * and password here. The API verifies the token (hashed, single-use,
 * 7-day expiry) and creates the user + membership (§63).
 */
function InviteForm() {
  const params = useSearchParams();
  const [token, setToken] = useState(params.get("token") ?? "");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  async function onSubmit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await apiFetch("/invitations/accept", {
        method: "POST",
        body: JSON.stringify({ token: token.trim(), name: name.trim(), password }),
      });
      setDone(true);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Could not accept the invitation. Is the API running?");
    } finally {
      setBusy(false);
    }
  }

  const input: React.CSSProperties = {
    width: "100%", padding: "0.65rem 0.85rem", borderRadius: 6, border: "1px solid #333",
    background: "#000", color: "#fff", fontSize: "0.875rem", outline: "none", boxSizing: "border-box",
  };
  const primaryBtn: React.CSSProperties = {
    width: "100%", padding: "0.65rem", borderRadius: 6, border: "none", background: "#ededed",
    color: "#000", fontWeight: 500, fontSize: "0.875rem", cursor: "pointer", opacity: busy ? 0.6 : 1,
    display: "block", textAlign: "center", textDecoration: "none", boxSizing: "border-box",
  };

  return (
    <div style={{ minHeight: "100vh", display: "flex", alignItems: "center", justifyContent: "center", background: "#000", color: "#fff", fontFamily: "'Inter',-apple-system,sans-serif", padding: "1rem" }}>
      <div style={{ background: "#121212", borderRadius: 12, padding: "2rem", width: "100%", maxWidth: 400, border: "1px solid #222", boxShadow: "0 10px 40px rgba(0,0,0,0.8)" }}>
        <div style={{ display: "flex", flexDirection: "column", alignItems: "center", textAlign: "center" }}>
          <div style={{ background: "#111", width: 44, height: 44, borderRadius: "50%", display: "flex", alignItems: "center", justifyContent: "center", fontWeight: 700, fontSize: "1.15rem", marginBottom: "0.75rem", border: "1px solid #333" }}>DS</div>
          <h1 style={{ fontSize: "1.35rem", fontWeight: 600, marginBottom: "0.25rem", letterSpacing: "-0.025em" }}>Accept your invitation</h1>
          <p style={{ fontSize: "0.85rem", color: "#888", marginBottom: "0.85rem", lineHeight: 1.5 }}>
            DSRclone is invite-only. Paste the invitation token you were given, choose a password, and your account is created.
          </p>
          {done ? (
            <div style={{ width: "100%", display: "flex", flexDirection: "column", gap: "0.65rem" }}>
              <div style={{ border: "1px solid #333", borderRadius: 8, background: "#0a0a0a", padding: "1rem", fontSize: "0.85rem", color: "#bbb", lineHeight: 1.6 }}>
                Your account is ready. You can now sign in with your email and the password you just set.
              </div>
              <Link href="/login" style={primaryBtn}>Sign in</Link>
            </div>
          ) : (
            <form onSubmit={onSubmit} style={{ width: "100%", display: "flex", flexDirection: "column", gap: "0.65rem" }}>
              <input style={input} type="text" placeholder="Invitation token" aria-label="Invitation token" value={token} onChange={(e) => setToken(e.target.value)} autoComplete="off" required />
              <input style={input} type="text" placeholder="Full Name" aria-label="Full name" value={name} onChange={(e) => setName(e.target.value)} autoComplete="name" required />
              <input style={input} type="password" placeholder="Choose a password" aria-label="Password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" required />
              {error ? <p role="alert" style={{ margin: 0, fontSize: "0.85rem", color: "#fca5a5", textAlign: "left" }}>{error}</p> : null}
              <button type="submit" style={primaryBtn} disabled={busy}>{busy ? "Creating account…" : "Create my account"}</button>
              <p style={{ margin: 0, fontSize: "0.75rem", color: "#888", lineHeight: 1.5 }}>
                By accepting you agree to the <Link href="/legal/terms" style={{ color: "#bbb", textDecoration: "underline" }}>Terms of Service</Link> and <Link href="/legal/privacy" style={{ color: "#bbb", textDecoration: "underline" }}>Privacy Policy</Link> — and that you will only assess targets you own or are authorized to test.
              </p>
            </form>
          )}
          <div style={{ marginTop: "1.25rem", fontSize: "0.875rem", color: "#888" }}>
            Already have an account? <Link href="/login" style={{ color: "#fff", fontWeight: 500, textDecoration: "none" }}>Sign In</Link>
          </div>
        </div>
      </div>
    </div>
  );
}

export default function InvitePage() {
  return (
    <Suspense fallback={null}>
      <InviteForm />
    </Suspense>
  );
}
