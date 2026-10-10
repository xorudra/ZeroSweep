"use client";

import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { usePathname, useRouter } from "next/navigation";
import { apiFetch, clearToken, getToken, refreshAccessToken } from "./api-client";

interface AuthState { ready: boolean; authenticated: boolean; logout: () => void; }
const AuthContext = createContext<AuthState>({ ready: false, authenticated: false, logout: () => undefined });
export const useAuth = () => useContext(AuthContext);

/** Auth boundary: dashboard routes require a session; /login and the
 *  legal pages (/legal/*) are public — anyone must be able to read the
 *  Terms, Privacy Policy and the other published documents without an
 *  account (they are linked from the sign-in card for exactly that
 *  reason). The backend re-checks the JWT (and its server-side session,
 *  A7) on every request — this guard is UX only, never the security
 *  control. Access tokens live in memory only, so on a fresh page load
 *  the session is restored with one silent cookie refresh before
 *  deciding. */
const isPublicPath = (p: string) => p === "/login" || p === "/legal" || p.startsWith("/legal/");
export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<{ ready: boolean; authenticated: boolean }>({ ready: false, authenticated: false });
  const pathname = usePathname();
  const router = useRouter();

  useEffect(() => {
    let live = true;
    (async () => {
      let authenticated = Boolean(getToken());
      if (!authenticated) authenticated = await refreshAccessToken();
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
    setState({ ready: true, authenticated: false });
    router.replace("/login");
  };
  return <AuthContext.Provider value={{ ...state, logout }}>{children}</AuthContext.Provider>;
}
