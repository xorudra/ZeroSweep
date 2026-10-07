import type { CanonicalFindingView } from "./types";
import type { ReportFindingInput } from "./reporting";

/**
 * Prompt 20 controlled-test fixtures (§98–§112). Every record is
 * SYNTHETIC: example hosts (RFC 5737 / example.com), and all "secrets"
 * are obvious fixture markers that exist to prove they never survive
 * sanitization.
 */

let seq = 0;
export function fixtureFinding(partial: Partial<CanonicalFindingView> & { title: string }): CanonicalFindingView {
  seq += 1;
  return {
    id: `fx-${seq}`,
    workspaceId: "ws-fixture",
    description: "fixture finding",
    severity: "HIGH",
    confidence: 0.9,
    verificationStatus: "UNVERIFIED",
    lifecycleStatus: "NEW",
    firstSeen: new Date("2026-10-01T00:00:00Z"),
    ...partial,
  } as CanonicalFindingView;
}

export function resetFixtureSeq(): void { seq = 0; }

export type CorrFixture = CanonicalFindingView & { fingerprint: string; vulnClass?: string; ruleId?: string; componentPurl?: string };

/** §100 cross-domain chain: cloud exposure → host → HTTPS → web app → code → dependency. */
export function crossDomainChainFixture(): CorrFixture[] {
  resetFixtureSeq();
  const host = "203.0.113.10";
  return [
    { ...fixtureFinding({ title: "Security group exposes 443 to the internet", sourceDomain: "CLOUD", category: "PUBLIC_EXPOSURE", severity: "HIGH", host }), fingerprint: "fp-cloud", ruleId: "cloud-sg-open" },
    { ...fixtureFinding({ title: "HTTPS service discovered", sourceDomain: "NETWORK", category: "VULNERABILITY", severity: "MEDIUM", host }), fingerprint: "fp-net", ruleId: "svc-https" },
    { ...fixtureFinding({ title: "Reflected XSS on /search", sourceDomain: "WEB", category: "VULNERABILITY", severity: "HIGH", cwe: "CWE-79", endpoint: "https://example.com/search", host }), fingerprint: "fp-web", vulnClass: "XSS" },
    { ...fixtureFinding({ title: "Unsanitized input in search handler", sourceDomain: "SAST", category: "CODE_FINDING", severity: "MEDIUM", cwe: "CWE-79", endpoint: "https://example.com/search", host }), fingerprint: "fp-sast", vulnClass: "XSS" },
    { ...fixtureFinding({ title: "Vulnerable template library", sourceDomain: "SCA", category: "DEPENDENCY_VULNERABILITY", severity: "HIGH", cve: "CVE-2021-44228" }), fingerprint: "fp-sca" },
  ];
}

/** §101: one CVE across host/container/binary/dependency findings. */
export function cveClusterFixture(): CanonicalFindingView[] {
  resetFixtureSeq();
  return [
    fixtureFinding({ title: "Log4Shell on host service", sourceDomain: "NETWORK", cve: "CVE-2021-44228", severity: "CRITICAL" }),
    fixtureFinding({ title: "Log4Shell in container image", sourceDomain: "CONTAINER", cve: "CVE-2021-44228", severity: "CRITICAL" }),
    fixtureFinding({ title: "Log4Shell in binary dependency", sourceDomain: "BINARY", cve: "CVE-2021-44228", severity: "HIGH" }),
    fixtureFinding({ title: "Log4Shell in application dependency", sourceDomain: "SCA", cve: "CVE-2021-44228", severity: "CRITICAL" }),
  ];
}

/** §98 hostile external record: script tags, terminal escapes, oversized
 *  strings, malformed Unicode, a fake (javascript:) URL. */
export const HOSTILE_EXTERNAL_RECORD = {
  id: "dd-666",
  title: "<script>alert('xss')</script>SQL injection",
  description: "desc with terminal escape [31mRED[0m and a lone surrogate \uD800 here",
  severity: "Critical",
  url: "javascript:alert(1)",
  active: true,
  verified: false,
  duplicate: false,
  mitigated: false,
  false_p: false,
};

/** §109 report fixture: evidence carrying synthetic secret material. */
export function reportFindingsFixture(): ReportFindingInput[] {
  return [{
    id: "rep-1",
    title: "Session token reflected in response",
    description: "The endpoint reflected a session token. Authorization: Bearer FIXTURE_TOKEN_VALUE password=hunter2fixture",
    severity: "HIGH",
    priority: "P1",
    riskScore: 78,
    verificationStatus: "VERIFIED",
    lifecycleStatus: "CONFIRMED",
    sourceDomain: "WEB",
    category: "VULNERABILITY",
    cwe: "CWE-201",
    host: "example.com",
    endpoint: "https://example.com/account",
    evidenceSummaries: [
      "Cookie: session=FIXTURE_SESSION_VALUE",
      "-----BEGIN RSA PRIVATE KEY-----\nFIXTUREKEYMATERIAL\n-----END RSA PRIVATE KEY-----",
    ],
    evidenceFingerprints: ["sha256:evidence-1"],
    sources: ["nuclei", "zap"],
    remediation: "Rotate the session and stop reflecting tokens.",
    firstSeen: "2026-10-01T00:00:00.000Z",
  }];
}
