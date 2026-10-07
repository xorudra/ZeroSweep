/**
 * Recorded tool outputs for Prompt 7 fixture tests (§57–§60). These are
 * hand-recorded, scanner-shaped outputs against the documentation host
 * example.com (RFC 2606) and its documentation IP — no tool executed, no
 * network touched, and the findings inside exist ONLY because these
 * recorded outputs contain them. They are never seeded into a database or
 * shown as real scan results.
 */

export const NUCLEI_JSONL = [
  JSON.stringify({
    "template-id": "http-missing-security-headers",
    info: { name: "Missing Security Headers", severity: "low", description: "One or more security response headers are missing.", reference: ["https://owasp.org/www-project-secure-headers/"] },
    type: "http", host: "example.com", ip: "93.184.216.34", "matched-at": "https://example.com/",
    request: "GET / HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer fixture-secret-token\r\n\r\n",
    response: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nSet-Cookie: sessionid=fixture-session-value; Path=/\r\n\r\n<html>example</html>",
  }),
  JSON.stringify({
    "template-id": "cookie-no-httponly",
    info: { name: "Cookie Without HttpOnly Flag", severity: "low", description: "A cookie was set without the HttpOnly flag.", reference: [] },
    type: "http", host: "example.com", ip: "93.184.216.34", "matched-at": "https://example.com/login",
    request: "GET /login HTTP/1.1\r\nHost: example.com\r\n\r\n",
    response: "HTTP/1.1 200 OK\r\nSet-Cookie: prefs=dark; Path=/\r\n\r\n",
  }),
  JSON.stringify({
    "template-id": "tls-version",
    info: { name: "Weak TLS Version Supported", severity: "medium", description: "The server supports a deprecated TLS protocol version.", reference: [] },
    type: "ssl", host: "example.com", ip: "93.184.216.34", port: 443, "matched-at": "example.com:443", "matcher-name": "tls10",
    "extracted-results": ["tls10"],
  }),
  JSON.stringify({
    "template-id": "sqli-error-based",
    info: { name: "Error-Based SQL Injection Probe", severity: "high", description: "Intrusive probe — must never survive automated policy.", reference: [] },
    type: "http", host: "example.com", "matched-at": "https://example.com/search?q=1",
  }),
  JSON.stringify({
    "template-id": "brand-new-check-2099",
    info: { name: "Unreviewed Future Check", severity: "info", description: "Unknown template — defaults to REVIEW_REQUIRED.", reference: [] },
    type: "http", host: "example.com", "matched-at": "https://example.com/",
  }),
  "{this line is intentionally malformed",
].join("\n");

export const NIKTO_JSON = JSON.stringify({
  host: "example.com", ip: "93.184.216.34", port: 443, banner: "nginx/1.18.0",
  vulnerabilities: [
    { id: "000001", OSVDB: "0", method: "GET", url: "/", msg: "The anti-clickjacking X-Frame-Options header is not present." },
    { id: "000002", OSVDB: "3092", method: "GET", url: "/config/", msg: "/config/: Directory indexing found." },
    { id: "000003", OSVDB: "0", method: "GET", url: "/", msg: "Server: nginx/1.18.0 - nginx 1.18.0 appears to be outdated (current is at least 1.25.0)." },
    { id: "000004", OSVDB: "0", method: "GET", url: "/", msg: "Allowed HTTP Methods: GET, POST, OPTIONS, HEAD, TRACE." },
    { id: "000005", OSVDB: "0", method: "GET", url: "/", msg: "Interesting banner line recorded by the operator." },
  ],
});

export const TESTSSL_JSON = JSON.stringify([
  { ip: "example.com/93.184.216.34", port: "443", severity: "OK", id: "SSLv3", finding: "not offered" },
  { ip: "example.com/93.184.216.34", port: "443", severity: "LOW", id: "TLS1", finding: "offered (deprecated)" },
  { ip: "example.com/93.184.216.34", port: "443", severity: "MEDIUM", id: "cipherlist_3DES", finding: "Triple DES ciphers offered", cwe: "CWE-327" },
  { ip: "example.com/93.184.216.34", port: "443", severity: "LOW", id: "HSTS", finding: "not offered" },
  { ip: "example.com/93.184.216.34", port: "443", severity: "INFO", id: "cert_notAfter", finding: "Certificate expires 2027-06-01" },
  { ip: "example.com/93.184.216.34", port: "443", severity: "OK", id: "cert_expiration_status", finding: "not expired" },
]);

export const TESTSSL_EXPIRED_JSON = JSON.stringify([
  { ip: "example.com/93.184.216.34", port: "443", severity: "HIGH", id: "cert_expiration_status", finding: "expired" },
]);

export const SSLYZE_JSON = JSON.stringify({
  server_scan_results: [{
    server_location: { hostname: "example.com", port: 443, ip_address: "93.184.216.34" },
    scan_status: "COMPLETED_SUCCESS",
    scan_result: {
      ssl_2_0_cipher_suites: { result: { accepted_cipher_suites: [] } },
      ssl_3_0_cipher_suites: { result: { accepted_cipher_suites: [] } },
      tls_1_0_cipher_suites: { result: { accepted_cipher_suites: [{ cipher_suite: { name: "TLS_RSA_WITH_AES_128_CBC_SHA" } }] } },
      tls_1_1_cipher_suites: { result: { accepted_cipher_suites: [] } },
      tls_1_2_cipher_suites: { result: { accepted_cipher_suites: [{ cipher_suite: { name: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" } }] } },
      tls_1_3_cipher_suites: { result: { accepted_cipher_suites: [{ cipher_suite: { name: "TLS_CHACHA20_POLY1305_SHA256" } }] } },
      certificate_info: {
        result: {
          certificate_deployments: [{
            received_certificate_chain: [{ subject: { rfc4514_string: "CN=example.com" }, not_after: "2027-06-01T00:00:00" }],
            path_validation_results: [{ trust_store: { name: "Mozilla" }, result: "SUCCESS" }],
          }],
        },
      },
      heartbleed: { result: { is_vulnerable_to_heartbleed: false } },
      robot: { result: { robot_result: "NOT_VULNERABLE" } },
    },
  }],
});
