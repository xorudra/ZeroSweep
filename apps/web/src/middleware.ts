import { NextRequest, NextResponse } from "next/server";

/**
 * Server-side auth routing: decide the right page BEFORE anything paints,
 * so there is never a spinner and never a flash of the wrong page.
 *
 * - No `zerosweep_session` cookie  -> protected pages redirect to /login,
 *   public pages (/login, /invite, /legal/*) render directly.
 * - Cookie present on a document load -> validated once against the API's
 *   read-only session check (same container, 127.0.0.1:4000). Valid: the
 *   page renders directly (/login bounces to /). Invalid (401): treated
 *   like no cookie, so even an expired session lands directly on /login.
 * - The check does NOT rotate the credential, so there is no Set-Cookie
 *   to forward and no race with the client's own refresh. A short-lived
 *   readable `zs_v` marker tells the client the load was validated, so
 *   it paints immediately instead of spinning on its own refresh round-trip.
 * - API unreachable -> fail open; the client's own auth check backstops.
 * - RSC / prefetch requests -> presence check only; the running client
 *   owns auth there, no API call, no rotation.
 */
const SESSION_COOKIE = "zerosweep_session";
const VALIDATED_MARKER = "zs_v";
// Set when the middleware determined there is NO live session for this load,
// so the client can paint the signed-out outcome immediately instead of
// spinning on its own refresh round-trip.
const ANON_MARKER = "zs_a";
const API_INTERNAL = process.env.API_INTERNAL_URL ?? "http://127.0.0.1:4000";

function isPublicPath(pathname: string): boolean {
  return (
    pathname === "/login" ||
    pathname === "/invite" ||
    pathname.startsWith("/login/") ||
    pathname.startsWith("/invite/") ||
    pathname.startsWith("/legal/")
  );
}

function isRsc(req: NextRequest): boolean {
  return req.headers.get("rsc") === "1" || req.headers.get("next-router-prefetch") === "1";
}

function nextWithAuth(req: NextRequest, auth: "valid" | "anon"): NextResponse {
  // Tell the page's server render the verdict via a request header, so the
  // very first paint (SSR) is already the right page — no spinner even
  // before hydration. The readable cookies below remain as a client-side
  // fallback.
  const requestHeaders = new Headers(req.headers);
  requestHeaders.set("x-zs-auth", auth);
  return NextResponse.next({ request: { headers: requestHeaders } });
}

export async function middleware(req: NextRequest): Promise<NextResponse> {
  const { pathname } = req.nextUrl;
  const session = req.cookies.get(SESSION_COOKIE)?.value;
  const publicPath = isPublicPath(pathname);

  // No session cookie: route on presence alone — instant, no API call.
  // The anon marker lets the client paint the outcome without its own
  // refresh round-trip.
  if (!session) {
    const res = publicPath
      ? nextWithAuth(req, "anon")
      : NextResponse.redirect(new URL("/login", req.url));
    res.cookies.delete(VALIDATED_MARKER);
    res.cookies.set(ANON_MARKER, "1", { path: "/", maxAge: 60, sameSite: "lax" });
    return res;
  }

  // Client-side navigations: the running client owns auth; presence is enough.
  // Keep the markers from going stale across tabs.
  if (isRsc(req)) {
    const res = NextResponse.next();
    if (session) res.cookies.delete(ANON_MARKER);
    else res.cookies.delete(VALIDATED_MARKER);
    return res;
  }

  // Full page load with a session cookie: validate once (read-only, no
  // rotation, so nothing to forward and no race with the client's refresh).
  let apiRes: Response;
  try {
    apiRes = await fetch(`${API_INTERNAL}/api/v1/auth/session/check`, {
      headers: {
        cookie: `${SESSION_COOKIE}=${session}`,
        "x-request-id": crypto.randomUUID(),
      },
    });
  } catch {
    // API unreachable: fail open, the client's own check backstops.
    return NextResponse.next();
  }

  if (apiRes.status === 401) {
    // Session dead: same routing as no cookie — direct login, no flash.
    const res = publicPath
      ? nextWithAuth(req, "anon")
      : NextResponse.redirect(new URL("/login", req.url));
    res.cookies.delete(VALIDATED_MARKER);
    res.cookies.set(ANON_MARKER, "1", { path: "/", maxAge: 60, sameSite: "lax" });
    return res;
  }
  if (!apiRes.ok) {
    // Unexpected API error: fail open, the client's own check backstops.
    return NextResponse.next();
  }

  const res =
    pathname === "/login"
      ? NextResponse.redirect(new URL("/", req.url))
      : nextWithAuth(req, "valid");
  res.cookies.delete(ANON_MARKER);
  res.cookies.set(VALIDATED_MARKER, "1", { path: "/", maxAge: 60, sameSite: "lax" });
  return res;
}

export const config = {
  matcher: ["/((?!api|_next/static|_next/image|favicon.ico|.*\\..*).*)"],
};
