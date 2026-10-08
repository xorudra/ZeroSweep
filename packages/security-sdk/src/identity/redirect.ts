/** Post-login redirect validation (§108) + CORS origin policy (§107). */
export function validatePostLoginRedirect(target: string | null | undefined, fallback = "/"): string {
  if (!target) return fallback;
  if (!target.startsWith("/") || target.startsWith("//") || target.startsWith("/\\")) return fallback;
  try {
    const url = new URL(target, "https://app.invalid");
    if (url.origin !== "https://app.invalid") return fallback;
    return url.pathname + url.search;
  } catch {
    return fallback;
  }
}

/** Credentialed CORS only for explicitly trusted origins — never wildcard. */
export function corsOriginAllowed(origin: string | null, trustedOrigins: string[]): string | null {
  if (!origin) return null;
  if (trustedOrigins.includes("*")) return null; // wildcard + credentials is forbidden (§143)
  return trustedOrigins.includes(origin) ? origin : null;
}
