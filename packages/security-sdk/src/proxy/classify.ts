/**
 * Traffic classification helpers (Prompt 8 §46–§52). Everything here is
 * INVENTORY classification — labels on endpoints/forms/transactions that
 * later phases consume. Nothing here submits a form, follows a logout, or
 * probes an endpoint: classification only reads already-observed traffic.
 */

/** Form safety classification (§46). Conservative profiles submit only
 *  SAFE forms; UNKNOWN is never auto-submitted; SENSITIVE/DESTRUCTIVE are
 *  never auto-submitted by ANY automated profile in this phase. */
export type FormSafety = "SAFE" | "UNKNOWN" | "SENSITIVE" | "DESTRUCTIVE";

const DESTRUCTIVE_HINTS = ["delete", "remove", "destroy", "drop", "purge", "terminate", "wipe", "reset-password", "deactivate"];
const SENSITIVE_HINTS = ["password", "passwd", "payment", "card", "cvv", "ssn", "iban", "account", "transfer", "admin", "role", "permission"];

export function classifyFormSafety(input: { action?: string; method?: string; fieldNames: string[] }): FormSafety {
  const hay = `${input.action ?? ""} ${input.fieldNames.join(" ")}`.toLowerCase();
  if (DESTRUCTIVE_HINTS.some((h) => hay.includes(h))) return "DESTRUCTIVE";
  if (SENSITIVE_HINTS.some((h) => hay.includes(h))) return "SENSITIVE";
  // A plain GET form with innocuous fields (search/filter style) is the
  // only shape classified SAFE; everything else stays UNKNOWN.
  if ((input.method ?? "GET").toUpperCase() === "GET" && input.fieldNames.length > 0) return "SAFE";
  if ((input.method ?? "GET").toUpperCase() === "GET") return "SAFE";
  return "UNKNOWN";
}

/** Logout detection (§47): authenticated crawling must not follow or
 *  submit logout actions — doing so would destroy the very session being
 *  tested and produce misleading "expired session" results. */
const LOGOUT_PATH_RE = /\/(logout|log-out|signout|sign-out|endsession|end-session)(\/|$|\?)/i;
export function isLogoutUrl(url: string): boolean {
  try {
    return LOGOUT_PATH_RE.test(new URL(url).pathname);
  } catch {
    return LOGOUT_PATH_RE.test(url);
  }
}

/** API traffic classification (§50): what kind of API an observed endpoint
 *  appears to be, from URL + content type + path conventions only. */
export type ApiKind = "REST" | "GRAPHQL" | "JSON_API" | "WEB";
export function classifyApiKind(url: string, contentType?: string): ApiKind {
  let path = url;
  try { path = new URL(url).pathname; } catch { /* keep raw */ }
  if (isGraphQlEndpoint(url)) return "GRAPHQL";
  const ct = (contentType ?? "").toLowerCase();
  if (ct.includes("application/vnd.api+json")) return "JSON_API";
  if (/\/(api|rest)(\/v\d+)?(\/|$)/i.test(path) || ct.includes("application/json")) {
    return ct.includes("application/json") || /\/(api|rest)(\/|$)/i.test(path) ? "REST" : "WEB";
  }
  return "WEB";
}

/** GraphQL detection (§51): path conventions only in this phase — no
 *  introspection or enumeration is performed or implied. */
export function isGraphQlEndpoint(url: string): boolean {
  let path = url;
  try { path = new URL(url).pathname; } catch { /* keep raw */ }
  return /\/(graphql|gql|graphiql)(\/|$)/i.test(path) || /[?&]query=\{\s*(__schema|__typename|[a-zA-Z])/.test(url);
}

/** OpenAPI/Swagger document detection (§52): when observed traffic points
 *  at a spec document, it is stored as an artifact REFERENCE and its
 *  documented endpoints are normalized SEPARATELY — a document's contents
 *  are never trusted as scope. */
export function isOpenApiDocumentUrl(url: string): boolean {
  let path = url;
  try { path = new URL(url).pathname.toLowerCase(); } catch { path = url.toLowerCase(); }
  return /(openapi|swagger)(\.(json|ya?ml))?$/.test(path)
    || path.endsWith("/swagger.json") || path.endsWith("/openapi.json")
    || path.includes("/swagger-ui") || path.endsWith("/api-docs") || path.endsWith("/v3/api-docs");
}

/** WebSocket URL detection (§49). */
export function isWebSocketUrl(url: string): boolean {
  return /^wss?:\/\//i.test(url);
}
