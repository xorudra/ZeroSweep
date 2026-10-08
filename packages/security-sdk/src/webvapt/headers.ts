/**
 * Header / CORS / CSRF analysis (Prompt 32 §86–§89).
 *
 * These are pure analyses over an OBSERVED response (fixture or
 * connector-imported) — the platform does not need to send a single
 * extra request to run them. Severity is contextual (§87): a missing
 * header on a JSON API is not the same finding as a missing header on
 * a session-cookie HTML application, and none of them is automatically
 * high severity.
 */

export interface HeaderObservation {
  url: string;
  contentType?: string;
  headers: Record<string, string>;
  /** Cookie attributes observed on Set-Cookie (names only §33). */
  setCookieAttributes?: string[];
  /** The page sets/uses cookies for a session (§89 context). */
  sessionCookies?: boolean;
  /** Forms observed on the page carry anti-CSRF tokens (§89). */
  formsHaveCsrfTokens?: boolean;
}

export interface HeaderFindingDraft {
  category: "SECURITY_HEADERS" | "CORS" | "CSRF" | "COOKIE";
  title: string;
  severity: "INFORMATIONAL" | "LOW" | "MEDIUM" | "HIGH";
  cwe: string;
  evidence: string;
}

function h(headers: Record<string, string>, name: string): string | undefined {
  const key = Object.keys(headers).find((k) => k.toLowerCase() === name.toLowerCase());
  return key ? headers[key] : undefined;
}

export function analyzeHeaders(obs: HeaderObservation): HeaderFindingDraft[] {
  const out: HeaderFindingDraft[] = [];
  const isHtml = (obs.contentType ?? "").includes("text/html");
  const isApi = (obs.contentType ?? "").includes("json");
  const push = (f: HeaderFindingDraft) => out.push(f);

  if (!h(obs.headers, "strict-transport-security") && obs.url.startsWith("https://")) {
    push({
      category: "SECURITY_HEADERS", title: "Missing Strict-Transport-Security header", cwe: "CWE-319",
      severity: isHtml ? "LOW" : "INFORMATIONAL",
      evidence: "HSTS absent on HTTPS response; impact is contextual (session-bearing HTML > stateless API)",
    });
  }
  const csp = h(obs.headers, "content-security-policy");
  if (isHtml && !csp) {
    push({ category: "SECURITY_HEADERS", title: "Missing Content-Security-Policy on HTML response", cwe: "CWE-693", severity: "LOW", evidence: "HTML served without CSP; defence-in-depth gap, not a standalone vulnerability" });
  }
  if (csp && /unsafe-inline|unsafe-eval/.test(csp) && !/nonce-|sha256-/.test(csp)) {
    push({ category: "SECURITY_HEADERS", title: "Content-Security-Policy allows unsafe-inline/unsafe-eval without nonce or hash", cwe: "CWE-693", severity: "LOW", evidence: `CSP: ${csp.slice(0, 120)}` });
  }
  if (!h(obs.headers, "x-content-type-options")) {
    push({ category: "SECURITY_HEADERS", title: "Missing X-Content-Type-Options header", cwe: "CWE-693", severity: "INFORMATIONAL", evidence: "nosniff not declared" });
  }
  const xfo = h(obs.headers, "x-frame-options");
  const frameAncestors = csp?.match(/frame-ancestors[^;]*/)?.[0];
  if (isHtml && !xfo && !frameAncestors) {
    push({ category: "SECURITY_HEADERS", title: "No frame-ancestors / X-Frame-Options protection on HTML response", cwe: "CWE-1021", severity: "LOW", evidence: "clickjacking protection absent for an HTML page" });
  }
  if (isApi && !xfo && !frameAncestors) {
    // §87: JSON APIs are not frameable content — recorded, not a finding.
  }
  const cookies = obs.setCookieAttributes ?? [];
  for (const attr of cookies) {
    const missing: string[] = [];
    if (!/;\s*HttpOnly/i.test(attr)) missing.push("HttpOnly");
    if (!/;\s*Secure/i.test(attr) && obs.url.startsWith("https://")) missing.push("Secure");
    if (!/;\s*SameSite=/i.test(attr)) missing.push("SameSite");
    if (missing.length > 0) {
      push({
        category: "COOKIE", title: `Cookie missing protective attributes: ${missing.join(", ")}`, cwe: "CWE-1004",
        severity: missing.includes("Secure") || missing.includes("HttpOnly") ? "LOW" : "INFORMATIONAL",
        evidence: "attribute summary only — cookie values are never recorded (§33)",
      });
    }
  }
  return out;
}

/** §88: safe CORS analysis over observed response headers. */
export function analyzeCors(obs: HeaderObservation & { requestOrigin?: string }): HeaderFindingDraft[] {
  const acao = h(obs.headers, "access-control-allow-origin");
  const acac = h(obs.headers, "access-control-allow-credentials");
  if (!acao) return [];
  if (acao === "*" && acac?.toLowerCase() === "true") {
    // Browsers reject this combination; it is a misconfiguration smell, not exploitable as-is.
    return [{ category: "CORS", title: "CORS wildcard origin combined with credentials flag", cwe: "CWE-942", severity: "LOW", evidence: "ACAO '*' with ACAC true — browsers reject the combination; indicates unsafe CORS intent" }];
  }
  if (obs.requestOrigin && acao === obs.requestOrigin && acac?.toLowerCase() === "true") {
    return [{ category: "CORS", title: "CORS reflects arbitrary Origin with credentials allowed", cwe: "CWE-942", severity: "MEDIUM", evidence: "response reflected the request Origin and allows credentials — any site may read authenticated responses" }];
  }
  if (acao === "null" && acac?.toLowerCase() === "true") {
    return [{ category: "CORS", title: "CORS allows 'null' origin with credentials", cwe: "CWE-942", severity: "LOW", evidence: "ACAO 'null' with credentials — sandboxed documents can obtain the null origin" }];
  }
  return [];
}

/** §89: CSRF posture from metadata — no state-changing proof is sent. */
export function analyzeCsrf(obs: HeaderObservation): HeaderFindingDraft[] {
  if (!obs.sessionCookies) return [];
  const samesiteStrictOrLax = (obs.setCookieAttributes ?? []).some((a) => /SameSite=(Strict|Lax)/i.test(a));
  if (obs.formsHaveCsrfTokens) return [];
  if (samesiteStrictOrLax) {
    return [{ category: "CSRF", title: "Forms lack anti-CSRF tokens; SameSite cookie policy partially mitigates", cwe: "CWE-352", severity: "INFORMATIONAL", evidence: "session cookies carry SameSite=Lax/Strict; token absence recorded as defence-in-depth note (§89)" }];
  }
  return [{ category: "CSRF", title: "Session forms without anti-CSRF tokens and no SameSite mitigation", cwe: "CWE-352", severity: "MEDIUM", evidence: "form/cookie metadata indicates state-changing forms rely on ambient cookies only — candidate requiring governed verification, not a state-changing proof (§89)" }];
}
