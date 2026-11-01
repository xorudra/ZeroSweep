import { NextRequest, NextResponse } from "next/server";

/**
 * Server-side auth routing: decide the right page BEFORE anything paints,
 * so there is never a spinner and never a flash of the wrong page.
 *
 * - No `zerosweep_session` cookie  -> protected pages redirect to /login,
 *   public pages (/login, /invite, /legal/*) render directly.
 * - Cookie present on a document load -> validated once against the API's
 *   refresh endpoint (same container, 127.0.0.1:4000). Valid: the page
 *   renders directly (/login bounces to /). Invalid (401): treated like
 *   no cookie, so even an expired session lands directly on /login.
 * - The refresh ROTATES the session credential; the rotated Set-Cookie is
 *   forwarded on our response, and a short-lived readable `zs_v` marker
 *   tells the client it can skip its own refresh (which would 401 against
 *   the rotated credential) and paint immediately.
 * - API unreachable -> fail open; the client's own auth check backstops.
 * - RSC / prefetch requests -> presence check only; the running client
 *   owns auth there, no API call, no rotation.
 */
const SESSION_COOKIE = "zerosweep_session";
const VALIDATED_MARKER = "zs_v";
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

function forwardSetCookies(from: Headers, to: Headers): void {
  const getSetCookie = (from as unknown as { getSetCookie?: () => string[] }).getSetCookie;
  const cookies: string[] =
    typeof getSetCookie === "function"
      ? getSetCookie.call(from)
      : (() => {
          const single = from.get("set-cookie");
          return single ? [single] : [];
        })();
  for (const c of cookies) to.append("set-cookie", c);
}

export async function middleware(req: NextRequest): Promise<NextResponse> {
  const { pathname } = req.nextUrl;
  const session = req.cookies.get(SESSION_COOKIE)?.value;
  const publicPath = isPublicPath(pathname);

  // No session cookie: route on presence alone — instant, no API call.
  if (!session) {
    const res = publicPath
      ? NextResponse.next()
      : NextResponse.redirect(new URL("/login", req.url));
    res.cookies.delete(VALIDATED_MARKER);
    return res;
  }

  // Client-side navigations: the running client owns auth; presence is enough.
  if (isRsc(req)) return NextResponse.next();

  // Full page load with a session cookie: validate once via refresh.
  let apiRes: Response;
  try {
    apiRes = await fetch(`${API_INTERNAL}/api/v1/auth/refresh`, {
      method: "POST",
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
      ? NextResponse.next()
      : NextResponse.redirect(new URL("/login", req.url));
    res.cookies.delete(VALIDATED_MARKER);
    return res;
  }
  if (!apiRes.ok) {
    // Unexpected API error: fail open, the client's own check backstops.
    return NextResponse.next();
  }

  const res =
    pathname === "/login"
      ? NextResponse.redirect(new URL("/", req.url))
      : NextResponse.next();
  forwardSetCookies(apiRes.headers, res.headers);
  res.cookies.set(VALIDATED_MARKER, "1", { path: "/", maxAge: 60, sameSite: "lax" });
  return res;
}

export const config = {
  matcher: ["/((?!api|_next/static|_next/image|favicon.ico|.*\\..*).*)"],
};
