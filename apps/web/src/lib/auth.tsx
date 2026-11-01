"use client";

import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { usePathname, useRouter } from "next/navigation";
import { apiFetch, clearToken, getToken, refreshAccessToken } from "./api-client";

interface AuthState { ready: boolean; authenticated: boolean; logout: () => void; }
const AuthContext = createContext<AuthState>({ ready: false, authenticated: false, logout: () => undefined });
export const useAuth = () => useContext(AuthContext);

/** Auth boundary: dashboard routes require a session; /login, the
 *  invitation-acceptance page (/invite) and the legal pages (/legal/*)
 *  are public — anyone must be able to read the
 *  Terms, Privacy Policy and the other published documents without an
 *  account (they are linked from the sign-in card for exactly that
 *  reason). The backend re-checks the JWT (and its server-side session,
 *  A7) on every request — this guard is UX only, never the security
 *  control. Access tokens live in memory only, so on a fresh page load
 *  the session is restored with one silent cookie refresh before
 *  deciding. */
const isPublicPath = (p: string) => p === "/login" || p === "/invite" || p === "/legal" || p.startsWith("/legal/");

/** Readable marker the middleware sets after it has validated the session
 *  for this page load (read-only check, no rotation). When present, the
 *  client paints immediately and skips its own refresh round-trip. The
 *  access token fills in lazily via apiFetch's 401 -> refresh on the
 *  first data call. */
const VALIDATED_MARKER = "zs_v";
function hasValidatedMarker(): boolean {
  if (typeof document === "undefined") return false;
  return document.cookie.split(";").some((c) => c.trim().startsWith(VALIDATED_MARKER + "="));
}

/** Set by the middleware when it determined there is NO live session for
 *  this load: the client can paint the signed-out outcome immediately
 *  instead of spinning on its own refresh round-trip. */
const ANON_MARKER = "zs_a";
function hasAnonMarker(): boolean {
  if (typeof document === "undefined") return false;
  return document.cookie.split(";").some((c) => c.trim().startsWith(ANON_MARKER + "="));
}
export function AuthProvider({ children, initialAuth }: { children: ReactNode; initialAuth?: "valid" | "anon" | null }) {
  // The middleware's verdict (via the layout) lets the very first paint —
  // including the server render — be the right page. It is trusted exactly
  // once, for this load; later navigations run the normal check below.
  const serverDecided = useRef(initialAuth === "valid" || initialAuth === "anon");
  const [state, setState] = useState<{ ready: boolean; authenticated: boolean }>({
    ready: serverDecided.current,
    authenticated: initialAuth === "valid",
  });
  const pathname = usePathname();
  const router = useRouter();

  useEffect(() => {
    if (serverDecided.current) {
      serverDecided.current = false;
      return;
    }
    let live = true;
    (async () => {
      let authenticated: boolean;
      if (getToken()) {
        authenticated = true;
      } else if (hasValidatedMarker()) {
        // The middleware already validated the session for this load —
        // trust it and paint now instead of spinning on our own refresh.
        authenticated = true;
      } else if (hasAnonMarker()) {
        // The middleware already determined there is no live session —
        // skip the refresh round-trip and paint the outcome directly.
        authenticated = false;
      } else {
        authenticated = await refreshAccessToken();
      }
      if (!live) return;
      setState({ ready: true, authenticated });
      if (!authenticated && !isPublicPath(pathname)) router.replace("/login");
      if (authenticated && pathname === "/login") router.replace("/");
    })();
    return () => { live = false; };
  }, [pathname, router]);

  const logout = () => {
    // A7: revoke server-side too — that kills the session, every JWT
    // minted for it, and the refresh cookie. Best effort: the local
    // state clears regardless of the outcome.
    void apiFetch("/auth/logout", { method: "POST", body: JSON.stringify({}) }).catch(() => undefined);
    clearToken();
    document.cookie = `${VALIDATED_MARKER}=; Path=/; Max-Age=0`;
    setState({ ready: true, authenticated: false });
    router.replace("/login");
  };
  return (
    <AuthContext.Provider value={{ ...state, logout }}>
      {/* First-paint gate. The middleware already routes full page loads
          server-side (no session -> /login, valid session -> the page, so
          the spinner never shows in normal flows). This gate is the
          backstop: it holds protected pages until the auth check
          completes, and trusts the middleware's short-lived markers so a
          decided load paints instantly — zs_v (validated) for the page,
          zs_a (no live session) for the login form. /invite and /legal/*
          still paint instantly — no redirect-away applies there. */}
      {state.ready ||
      (pathname !== "/login" && (isPublicPath(pathname) || hasValidatedMarker())) ||
      (pathname === "/login" && hasAnonMarker()) ? (
        children
      ) : (
        <div
          role="status"
          aria-label="Loading"
          className="flex min-h-screen items-center justify-center bg-[#eef3f6]"
        >
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-[#1b6c80]/25 border-t-[#1b6c80]" />
        </div>
      )}
    </AuthContext.Provider>
  );
}
