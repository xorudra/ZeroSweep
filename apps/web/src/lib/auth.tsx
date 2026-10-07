"use client";

import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import { usePathname, useRouter } from "next/navigation";
import { clearToken, getToken } from "./api-client";

interface AuthState { ready: boolean; authenticated: boolean; logout: () => void; }
const AuthContext = createContext<AuthState>({ ready: false, authenticated: false, logout: () => undefined });
export const useAuth = () => useContext(AuthContext);

/** Auth boundary: dashboard routes require a token; /login is public.
 *  The backend re-checks the JWT and RBAC on every request — this guard is
 *  UX only, never the security control. */
export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<{ ready: boolean; authenticated: boolean }>({ ready: false, authenticated: false });
  const pathname = usePathname();
  const router = useRouter();

  useEffect(() => {
    const authenticated = Boolean(getToken());
    setState({ ready: true, authenticated });
    if (!authenticated && pathname !== "/login") router.replace("/login");
    if (authenticated && pathname === "/login") router.replace("/");
  }, [pathname, router]);

  const logout = () => { clearToken(); setState({ ready: true, authenticated: false }); router.replace("/login"); };
  return <AuthContext.Provider value={{ ...state, logout }}>{children}</AuthContext.Provider>;
}
