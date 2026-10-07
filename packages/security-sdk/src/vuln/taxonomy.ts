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
};

export function vulnClassFamily(vulnClass: string): string {
  return VULN_CLASS_FAMILIES[vulnClass] ?? vulnClass;
}

export function taxonomyFor(vulnClass: string): VulnClassInfo {
  return VULN_CLASS_TAXONOMY[vulnClass] ?? VULN_CLASS_TAXONOMY.GENERIC_VULNERABILITY!;
}
