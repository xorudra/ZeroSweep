/**
 * Curated vulnerability taxonomy (Prompt 7 §27/§28). CWE and OWASP values
 * come ONLY from this platform-maintained mapping, keyed by vulnerability
 * class — never from AI guessing and never from a technology name alone.
 * Mappings are versioned (OWASP Top 10 2021) so reports can state exactly
 * which taxonomy version produced them.
 */

export const OWASP_TAXONOMY_VERSION = "OWASP Top 10 2021";

export interface VulnClassInfo {
  /** Human title used when a scanner gives only a class-level signal. */
  title: string;
  /** Curated CWE (e.g. "CWE-327") — assigned only via this table (§27). */
  cwe?: string;
  /** OWASP Top 10 2021 category label (§28). */
  owaspCategory?: string;
  /** Remediation guidance shipped with the platform, not by the scanner. */
  remediation?: string;
  /** Technical-impact statement template for the class. */
  technicalImpact?: string;
}

export const VULN_CLASS_TAXONOMY: Record<string, VulnClassInfo> = {
  TLS_WEAK_PROTOCOL: {
    title: "Weak TLS Protocol Supported",
    cwe: "CWE-327",
    owaspCategory: "A02:2021 Cryptographic Failures",
    remediation: "Disable SSLv2, SSLv3, TLS 1.0 and TLS 1.1; support TLS 1.2+ only (prefer TLS 1.3) with strong cipher suites.",
    technicalImpact: "Legacy TLS protocols have known cryptographic weaknesses (e.g. POODLE, BEAST) that can allow decryption of intercepted traffic.",
  },
  TLS_WEAK_CIPHER: {
    title: "Weak TLS Cipher Suite Supported",
    cwe: "CWE-327",
    owaspCategory: "A02:2021 Cryptographic Failures",
    remediation: "Remove weak cipher suites (RC4, 3DES, DES, NULL, export-grade, anonymous DH) and prefer AEAD suites with forward secrecy.",
    technicalImpact: "Weak ciphers can be broken or downgraded, exposing session contents to an attacker able to observe traffic.",
  },
  TLS_CERTIFICATE_EXPIRED: {
    title: "Expired TLS Certificate",
    cwe: "CWE-298",
    owaspCategory: "A02:2021 Cryptographic Failures",
    remediation: "Renew the certificate before expiry and automate renewal/monitoring so expiry is caught in advance.",
    technicalImpact: "An expired certificate breaks client trust validation; users may be trained to bypass warnings, enabling man-in-the-middle attacks.",
  },
  TLS_CERTIFICATE_UNTRUSTED: {
    title: "TLS Certificate Chain Not Trusted",
    cwe: "CWE-295",
    owaspCategory: "A02:2021 Cryptographic Failures",
    remediation: "Deploy a complete certificate chain issued by a publicly trusted CA (or the organization's managed PKI) for this host.",
    technicalImpact: "Clients cannot reliably authenticate the server, weakening protection against impersonation and interception.",
  },
  TLS_CONFIGURATION: {
    title: "TLS Configuration Weakness",
    cwe: "CWE-327",
    owaspCategory: "A02:2021 Cryptographic Failures",
    remediation: "Review the TLS configuration against a current baseline (e.g. Mozilla intermediate/modern) and re-test.",
    technicalImpact: "A weak TLS configuration can reduce the confidentiality or integrity of data in transit.",
  },
  MISSING_SECURITY_HEADERS: {
    title: "Missing Security Response Header",
    cwe: "CWE-693",
    owaspCategory: "A05:2021 Security Misconfiguration",
    remediation: "Add the missing security response headers (e.g. X-Frame-Options/Content-Security-Policy frame-ancestors, X-Content-Type-Options, Strict-Transport-Security, Referrer-Policy) appropriate to the application.",
    technicalImpact: "Missing hardening headers remove browser-enforced protections against clickjacking, MIME sniffing and downgrade attacks.",
  },
  COOKIE_NO_HTTPONLY: {
    title: "Cookie Missing HttpOnly Flag",
    cwe: "CWE-1004",
    owaspCategory: "A05:2021 Security Misconfiguration",
    remediation: "Set the HttpOnly flag on cookies that do not need JavaScript access, especially session cookies.",
    technicalImpact: "Without HttpOnly, a cross-site scripting flaw can read the cookie and hijack the session.",
  },
  COOKIE_NO_SECURE: {
    title: "Cookie Missing Secure Flag",
    cwe: "CWE-614",
    owaspCategory: "A05:2021 Security Misconfiguration",
    remediation: "Set the Secure flag on cookies so they are only sent over HTTPS.",
    technicalImpact: "Cookies without Secure may be transmitted over plaintext HTTP and intercepted.",
  },
  COOKIE_NO_SAMESITE: {
    title: "Cookie Without SameSite Attribute",
    cwe: "CWE-1275",
    owaspCategory: "A05:2021 Security Misconfiguration",
    remediation: "Set an explicit SameSite attribute (Lax or Strict) on cookies, especially session cookies.",
    technicalImpact: "Without SameSite, cookies may be attached to cross-site requests, widening CSRF exposure.",
  },
  EXPOSED_FILE: {
    title: "Sensitive File Exposed",
    cwe: "CWE-538",
    owaspCategory: "A01:2021 Broken Access Control",
    remediation: "Remove the exposed file from the web root or deny access to it at the server; audit for other deployment artifacts.",
    technicalImpact: "Exposed configuration/source artifacts can leak credentials, paths and implementation details useful for further attacks.",
  },
  DIRECTORY_LISTING: {
    title: "Directory Listing Enabled",
    cwe: "CWE-548",
    owaspCategory: "A05:2021 Security Misconfiguration",
    remediation: "Disable directory indexing (e.g. `autoindex off` / `Options -Indexes`) on web-accessible directories.",
    technicalImpact: "Directory listings disclose file names and structure that aid targeted attacks.",
  },
  OUTDATED_SOFTWARE: {
    title: "Outdated Software Component",
    cwe: "CWE-1104",
    owaspCategory: "A06:2021 Vulnerable and Outdated Components",
    remediation: "Upgrade the component to a supported, patched release and subscribe to its security advisories.",
    technicalImpact: "Outdated components may carry publicly known vulnerabilities; presence here is a version observation, not proof of exploitability.",
  },
  INFORMATION_DISCLOSURE: {
    title: "Information Disclosure",
    cwe: "CWE-200",
    owaspCategory: "A05:2021 Security Misconfiguration",
    remediation: "Reduce the information returned to unauthenticated users (banners, error details, metadata) to the minimum required.",
    technicalImpact: "Disclosed implementation details help an attacker fingerprint the stack and select targeted techniques.",
  },
  SERVER_MISCONFIGURATION: {
    title: "Web Server Misconfiguration",
    cwe: "CWE-16",
    owaspCategory: "A05:2021 Security Misconfiguration",
    remediation: "Review the flagged server setting against the vendor hardening baseline and disable anything not required.",
    technicalImpact: "Permissive server settings can widen the attack surface beyond what the application intends to expose.",
  },
  CORS_MISCONFIGURATION: {
    title: "CORS Misconfiguration",
    cwe: "CWE-942",
    owaspCategory: "A05:2021 Security Misconfiguration",
    remediation: "Restrict Access-Control-Allow-Origin to trusted origins; never reflect arbitrary origins together with credentials.",
    technicalImpact: "Overly permissive CORS can let attacker sites read authenticated responses cross-origin.",
  },
  OPEN_REDIRECT: {
    title: "Open Redirect",
    cwe: "CWE-601",
    owaspCategory: "A01:2021 Broken Access Control",
    remediation: "Validate redirect destinations against an allowlist of local paths or trusted hosts.",
    technicalImpact: "Open redirects lend the trusted domain to phishing and can bypass redirect-based allowlists.",
  },
  XSS: {
    title: "Cross-Site Scripting",
    cwe: "CWE-79",
    owaspCategory: "A03:2021 Injection",
    remediation: "Apply context-appropriate output encoding and a Content-Security-Policy; validate input server-side.",
    technicalImpact: "Reflected/stored script injection executes attacker code in victims' browsers under the site's origin.",
  },
  GENERIC_VULNERABILITY: {
    title: "Vulnerability Reported by Scanner",
    owaspCategory: undefined,
    remediation: "Review the scanner evidence, confirm applicability, and apply the vendor guidance linked in the references.",
    technicalImpact: "See the scanner-provided description and evidence for the assessed impact.",
  },
  // Prompt 10: network-service classes. These are created ONLY from
  // detected-service evidence + the curated cleartext/management policy
  // (network/network-checks.ts) or from a governed SAFE NSE script whose
  // output confirms the condition — never from an open port alone (§37).
  CLEARTEXT_PROTOCOL_EXPOSURE: {
    title: "Cleartext Protocol Exposed",
    cwe: "CWE-319",
    owaspCategory: "A02:2021 Cryptographic Failures",
    remediation: "Disable the cleartext service or wrap/replace it with an encrypted equivalent (SSH for Telnet, FTPS/SFTP for FTP) and restrict exposure with network controls.",
    technicalImpact: "Credentials and session data traverse the network unencrypted and can be intercepted or modified by an on-path attacker.",
  },
  UNAUTHENTICATED_MANAGEMENT_API: {
    title: "Management API Exposed Without Authentication By Design",
    cwe: "CWE-862",
    owaspCategory: "A01:2021 Broken Access Control",
    remediation: "Bind the management API to a trusted interface/socket only, require authentication and TLS, and firewall it from untrusted networks.",
    technicalImpact: "The exposed management API (e.g. an unencrypted Docker endpoint) grants unauthenticated administrative control of the host to anyone who can reach it.",
  },
  SMB_SIGNING_NOT_REQUIRED: {
    title: "SMB Message Signing Not Required",
    cwe: "CWE-294",
    owaspCategory: "A02:2021 Cryptographic Failures",
    remediation: "Require SMB message signing (and SMB encryption where supported) via group policy / server configuration.",
    technicalImpact: "Without required message signing, SMB sessions are exposed to relay and man-in-the-middle attacks.",
  },
  // Prompt 9: API security classes. The OWASP category for these comes
  // from the OWASP API Security Top 10 2023 mapping (api/taxonomy.ts),
  // applied by API-engine producers — the web taxonomy intentionally
  // leaves owaspCategory undefined here so the two versions never mix.
  JWT_ALGORITHM_CONFIGURATION: {
    title: "JWT Algorithm Configuration Issue",
    cwe: "CWE-327",
    remediation: "Pin the expected signing algorithm server-side (asymmetric RS256/ES256 for public clients), reject 'none' and unexpected algorithms, and never let the token choose the verification algorithm or key type.",
    technicalImpact: "If the API accepts attacker-chosen algorithms (e.g. 'none' or symmetric verification of an asymmetric key), forged tokens may be accepted as genuine.",
  },
  JWT_MISSING_EXPIRY: {
    title: "JWT Without Expiry",
    cwe: "CWE-613",
    remediation: "Issue tokens with a bounded 'exp' claim and enforce expiry server-side; pair with refresh-token rotation for longer sessions.",
    technicalImpact: "A token that never expires remains usable indefinitely if leaked, with no natural revocation point.",
  },
  JWT_EXCESSIVE_LIFETIME: {
    title: "JWT With Excessively Long Lifetime",
    cwe: "CWE-613",
    remediation: "Shorten access-token lifetimes to the minimum the application needs and use refresh tokens for session continuity.",
    technicalImpact: "Long-lived bearer tokens widen the window in which a stolen token can be replayed.",
  },
  JWT_SENSITIVE_CLAIMS: {
    title: "Sensitive Information in JWT Claims",
    cwe: "CWE-359",
    remediation: "Keep secrets, credentials, and unnecessary personal data out of token claims — tokens are routinely logged, stored client-side, and readable by anyone holding them.",
    technicalImpact: "JWT payloads are only base64url-encoded, not encrypted: anyone with the token can read every claim.",
  },
  JWT_ISSUER_AUDIENCE_MISMATCH: {
    title: "JWT Issuer/Audience Inconsistency",
    cwe: "CWE-441",
    remediation: "Configure and enforce expected 'iss' and 'aud' values server-side so tokens minted for one service are not accepted by another.",
    technicalImpact: "Tokens accepted across issuers or audiences enable token confusion between services and environments.",
  },
  EXPOSED_API_DOCUMENTATION: {
    title: "Exposed API Documentation",
    cwe: "CWE-200",
    remediation: "Restrict interactive API documentation (Swagger UI / OpenAPI documents) to authenticated or internal audiences in production, or accept the exposure explicitly as a documented risk decision.",
    technicalImpact: "Public API documentation hands attackers a complete, machine-readable map of endpoints, parameters and schemas.",
  },
  EXPOSED_DEBUG_ENDPOINT: {
    title: "Exposed Debug / Management Endpoint",
    cwe: "CWE-489",
    remediation: "Disable debug/management endpoints in production or protect them with strong authentication and network restrictions.",
    technicalImpact: "Debug and management endpoints can disclose internals or permit administrative actions beyond the intended API surface.",
  },
  API_RESPONSE_CONFORMANCE: {
    title: "API Response Does Not Conform to Its Schema",
    remediation: "Align the implementation with the published schema (status codes, content types, response bodies) — clients and security controls make decisions based on the documented contract.",
    technicalImpact: "Contract drift hides behaviour from reviewers and clients; undocumented responses may carry data the schema never approved.",
  },
  API_SERVER_ERROR: {
    title: "API Returns Server Errors for Valid Requests",
    cwe: "CWE-703",
    remediation: "Fix the server-side fault for the affected operation and add regression coverage; ensure error responses do not leak stack traces or internals.",
    technicalImpact: "Server errors on valid input indicate unhandled code paths; verbose errors can disclose implementation details useful to attackers.",
  },
};

/** Vulnerability-class "families": classes close enough that two findings
 *  in the same family on the same asset+endpoint are POSSIBLE duplicates
 *  (§20) even when their exact fingerprints differ. */
export const VULN_CLASS_FAMILIES: Record<string, string> = {
  TLS_WEAK_PROTOCOL: "TLS",
  TLS_WEAK_CIPHER: "TLS",
  TLS_CERTIFICATE_EXPIRED: "TLS",
  TLS_CERTIFICATE_UNTRUSTED: "TLS",
  TLS_CONFIGURATION: "TLS",
  COOKIE_NO_HTTPONLY: "COOKIE",
  COOKIE_NO_SECURE: "COOKIE",
  COOKIE_NO_SAMESITE: "COOKIE",
  MISSING_SECURITY_HEADERS: "HEADERS",
  JWT_ALGORITHM_CONFIGURATION: "JWT",
  JWT_MISSING_EXPIRY: "JWT",
  JWT_EXCESSIVE_LIFETIME: "JWT",
  JWT_SENSITIVE_CLAIMS: "JWT",
  JWT_ISSUER_AUDIENCE_MISMATCH: "JWT",
  EXPOSED_API_DOCUMENTATION: "EXPOSURE",
  EXPOSED_DEBUG_ENDPOINT: "EXPOSURE",
  CLEARTEXT_PROTOCOL_EXPOSURE: "NETWORK_EXPOSURE",
  UNAUTHENTICATED_MANAGEMENT_API: "NETWORK_EXPOSURE",
  SMB_SIGNING_NOT_REQUIRED: "NETWORK_EXPOSURE",
};

export function vulnClassFamily(vulnClass: string): string {
  return VULN_CLASS_FAMILIES[vulnClass] ?? vulnClass;
}

export function taxonomyFor(vulnClass: string): VulnClassInfo {
  return VULN_CLASS_TAXONOMY[vulnClass] ?? VULN_CLASS_TAXONOMY.GENERIC_VULNERABILITY!;
}
