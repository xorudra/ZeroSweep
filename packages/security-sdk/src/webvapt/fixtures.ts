/**
 * Recorded fixture outputs for the Prompt 32 tools. Every fixture is a
 * synthetic recording against a documentation target
 * (staging.example.com / RFC 5737-style fixture app) — no fixture was
 * produced against a real system, and the planted fixture credential
 * below exists ONLY to prove redaction (§178): it must never appear in
 * any parsed finding, evidence string, log or report.
 */

export const FIXTURE_PLANTED_TOKEN = "FIXTURE-TOKEN-dsr32-secret-9f27";

/** Dalfox JSON: one verified + one reflected-only marker result. */
export const DALFOX_FIXTURE = JSON.stringify([
  {
    type: "V",
    param: "q",
    evidence: "dsr-marker reflected unencoded in attribute context",
    poc: "https://staging.example.com/search?q=dsr-marker",
    url: "https://staging.example.com/search?q=dsr-marker",
  },
  {
    type: "R",
    param: "ref",
    evidence: "reflection observed, encoding uncertain",
    poc: "https://staging.example.com/go?ref=dsr-marker",
    url: "https://staging.example.com/go?ref=dsr-marker",
  },
]);

/** XSStrike console log for the same controlled fixture app. */
export const XSSTRIKE_FIXTURE = [
  "[*] Checking parameter: q",
  "[+] Reflection Found in Parameter: q at https://staging.example.com/search?q=dsr-marker",
  "[*] Scan finished",
].join("\n");

/** SQLmap console output: boolean-based blind detection on parameter id. */
export const SQLMAP_FIXTURE = [
  "sqlmap/1.8#stable — automatic SQL injection and database takeover tool",
  "[INFO] testing connection to the target URL",
  "[INFO] checking if the target is protected by some kind of WAF/IPS",
  "[INFO] testing if the target URL content is stable",
  "GET parameter 'id' appears to be dynamic",
  "[INFO] heuristic (basic) test shows that GET parameter 'id' might be injectable",
  "[INFO] testing for SQL injection on GET parameter 'id'",
  "Parameter: id (GET)",
  "    Type: boolean-based blind",
  "    Title: AND boolean-based blind - WHERE or HAVING clause",
  "    Payload: id=1 AND 5713=5713",
  "[INFO] the back-end DBMS is MySQL",
  "the back-end DBMS is MySQL >= 5.0",
  `Authorization: Bearer ${FIXTURE_PLANTED_TOKEN}`,
].join("\n");

/** Commix console output: marker-based command injection detection. */
export const COMMIX_FIXTURE = [
  "commix 4.0 — Automated All-in-One OS Command Injection Exploitation Tool",
  "(*) Target URL: https://staging.example.com/ping?host=127.0.0.1",
  "[+] The 'host' parameter appears to be injectable via results-based command injection technique.",
  "[*] Command injection was identified — proof marker output classified and redacted by the platform.",
].join("\n");

/** SSTImap console output: engine identified via arithmetic marker. */
export const SSTIMAP_FIXTURE = [
  "SSTImap v1.2 — automatic SSTI detection tool",
  "[*] Testing parameter name",
  "[+] The parameter name appears to be injectable — identified template engine: Jinja2",
  "[*] Finished scan of https://staging.example.com/greet?name=dsr",
].join("\n");

/** WPScan JSON: vulnerable plugin + interesting finding. */
export const WPSCAN_FIXTURE = JSON.stringify({
  target_url: "https://staging.example.com/",
  wordpress_version: {
    number: "6.4.2",
    vulnerabilities: [
      { title: "WordPress < 6.4.3 - Authenticated Stored XSS", references: { cve: ["2024-24860"] } },
    ],
  },
  plugins: {
    "fixture-slider": {
      version: { number: "1.2.0" },
      vulnerabilities: [
        { title: "Fixture Slider < 1.2.1 - Reflected XSS", references: { cve: ["2023-99999"] } },
      ],
    },
  },
  themes: {},
  interesting_findings: [
    { to_s: "Upload directory has directory listing enabled: https://staging.example.com/wp-content/uploads/" },
  ],
});

/** A malformed recording: parser failure must be partial, never clean (§188). */
export const MALFORMED_FIXTURE = "{not json at all ;; ;; sqlmap partial line [INFO] test";

/** Fixture GraphQL operations (§184): one within limits, one excessive. */
export const GRAPHQL_OK_FIXTURE = "query GetUser { user { id name posts { title } } }";
export const GRAPHQL_EXCESSIVE_FIXTURE = `query Deep {
  a { b { c { d { e { f { g { h { i { j { k { l { m } } } } } } } } } } } }
}`;
