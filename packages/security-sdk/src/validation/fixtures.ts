import type { ValidationFindingView } from "./types";
import type {
  ConfigurationObservation,
  HttpObservation,
  ScannerRecheckObservation,
  ServiceObservation,
  TlsObservation,
} from "./validators";

/**
 * Controlled lab fixtures (Prompt 16 §83). Every fixture lives on
 * documentation/example destinations (RFC 5737 / *.fixture.example) and
 * carries RECORDED observations — no fixture ever touches a network.
 * The set covers: HTTP header issue, TLS issue, synthetic XSS scanner
 * result, synthetic SQLi scanner result, exposed test service, cloud
 * configuration, Kubernetes posture and AD graph fixtures (§83), plus a
 * "fixed" header target and a redaction-trap response (§91).
 */

export const FIXTURE_SCOPE_RULES = {
  includeHosts: ["*.fixture.example", "app.fixture.example", "tls.fixture.example", "svc.fixture.example", "fixed.fixture.example"],
  excludeHosts: [] as string[],
  includeCidrs: [] as string[],
  allowedPorts: [] as number[],
  allowedPaths: [] as string[],
  excludedPaths: [] as string[],
};

export const HEADER_FINDING: ValidationFindingView = {
  id: "finding-header",
  title: "Missing Content-Security-Policy header",
  vulnClass: "MISSING_SECURITY_HEADER",
  host: "app.fixture.example",
  endpoint: "https://app.fixture.example/",
  sources: ["httpx"],
  assetCriticality: "MEDIUM",
};

export const FIXED_HEADER_FINDING: ValidationFindingView = {
  id: "finding-header-fixed",
  title: "Missing Content-Security-Policy header",
  vulnClass: "MISSING_SECURITY_HEADER",
  host: "fixed.fixture.example",
  endpoint: "https://fixed.fixture.example/",
  sources: ["httpx"],
  assetCriticality: "MEDIUM",
};

export const TLS_FINDING: ValidationFindingView = {
  id: "finding-tls",
  title: "TLS 1.0 enabled",
  vulnClass: "WEAK_TLS_CONFIGURATION",
  host: "tls.fixture.example",
  port: 8443,
  sources: ["testssl"],
  assetCriticality: "HIGH",
};

export const SERVICE_FINDING: ValidationFindingView = {
  id: "finding-service",
  title: "Cleartext service exposed (telnet)",
  vulnClass: "CLEARTEXT_SERVICE",
  host: "svc.fixture.example",
  port: 2323,
  sources: ["nmap"],
  assetCriticality: "MEDIUM",
};

/** §16: SQLi findings validate ONLY via scanner-evidence recheck. */
export const SQLI_FINDING: ValidationFindingView = {
  id: "finding-sqli",
  title: "SQL injection (scanner detection)",
  vulnClass: "SQL_INJECTION",
  host: "app.fixture.example",
  endpoint: "https://app.fixture.example/search?q=fixture",
  sources: ["nuclei"],
  assetCriticality: "HIGH",
};

/** §17: XSS findings validate via isolated scanner recheck only. */
export const XSS_FINDING: ValidationFindingView = {
  id: "finding-xss",
  title: "Reflected XSS (scanner detection)",
  vulnClass: "CROSS_SITE_SCRIPTING",
  host: "app.fixture.example",
  endpoint: "https://app.fixture.example/reflect?input=fixture",
  sources: ["nuclei"],
  assetCriticality: "MEDIUM",
};

export const CLOUD_FINDING: ValidationFindingView = {
  id: "finding-cloud",
  title: "S3 bucket allows public access",
  vulnClass: "PUBLIC_STORAGE",
  cloudProvider: "AWS",
  cloudResourceId: "fixture-bucket",
  sources: ["prowler"],
  assetCriticality: "HIGH",
};

export const K8S_FINDING: ValidationFindingView = {
  id: "finding-k8s",
  title: "Privileged container in workload",
  vulnClass: "PRIVILEGED_CONTAINER",
  clusterRef: "fixture-cluster",
  sources: ["kubescape"],
  assetCriticality: "MEDIUM",
};

export const AD_FINDING: ValidationFindingView = {
  id: "finding-ad",
  title: "Unconstrained delegation configured",
  vulnClass: "UNCONSTRAINED_DELEGATION",
  directoryDomainId: "fixture-domain",
  directoryObjectId: "S-1-5-21-FIXTURE",
  sources: ["pingcastle"],
  assetCriticality: "HIGH",
};

export const SOURCE_FINDING: ValidationFindingView = {
  id: "finding-source",
  title: "SQL injection pattern in source (SAST)",
  vulnClass: "SQL_INJECTION",
  repositoryId: "fixture-repo",
  filePath: "src/search.ts",
  ruleId: "fixture-sqli-rule",
  sources: ["semgrep"],
};

export const CONTAINER_FINDING: ValidationFindingView = {
  id: "finding-container",
  title: "CVE-2021-44228 in image package log4j",
  vulnClass: "VULNERABLE_PACKAGE",
  cve: "CVE-2021-44228",
  imageDigest: "sha256:fixture-digest",
  componentPurl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
  sources: ["trivy"],
};

/** Recorded transport observations keyed for the fixture transport. */
export const FIXTURE_HTTP: Record<string, HttpObservation> = {
  "https://app.fixture.example/": {
    status: 200,
    headers: { "content-type": "text/html", "x-frame-options": "DENY" },
    bodyBytes: 1024,
    redirects: 0,
  },
  "https://fixed.fixture.example/": {
    status: 200,
    headers: { "content-type": "text/html", "content-security-policy": "default-src 'self'", "x-frame-options": "DENY" },
    bodyBytes: 1024,
    redirects: 0,
  },
  // §91 redaction trap: the recorded response carries live-looking
  // secrets in headers — evidence built from it must be sanitized
  // before it is stored or displayed anywhere.
  "https://app.fixture.example/reflect?input=fixture": {
    status: 200,
    headers: {
      "content-type": "text/html",
      authorization: "Bearer fixture-secret-token-12345",
      "set-cookie": "session=fixture-session-id-67890; HttpOnly",
      "x-api-key": "fixture-api-key-abcdef",
    },
    bodyBytes: 512,
    redirects: 0,
  },
  "https://app.fixture.example/search?q=fixture": {
    status: 200,
    headers: { "content-type": "application/json" },
    bodyBytes: 256,
    redirects: 0,
  },
};

export const FIXTURE_TLS: Record<string, TlsObservation> = {
  "tls.fixture.example:8443": {
    protocols: ["TLSv1.0", "TLSv1.2"],
    weakCiphers: [],
    certificateValid: true,
    issues: ["TLSv1.0 enabled"],
  },
};

export const FIXTURE_SERVICES: Record<string, ServiceObservation> = {
  "svc.fixture.example:2323": { open: true, product: "telnetd", banner: "fixture telnet banner" },
};

export const FIXTURE_CONFIGURATIONS: Record<string, ConfigurationObservation> = {
  "cloud:fixture-bucket": {
    issuePresent: true,
    detail: { publicAccess: true, encryptionAtRest: false, loggingEnabled: false },
  },
  "kubernetes:fixture-cluster": {
    issuePresent: true,
    detail: { privilegedContainers: 1, networkPolicyPresent: false },
  },
  "activedirectory:S-1-5-21-FIXTURE": {
    issuePresent: true,
    detail: { unconstrainedDelegation: true, trustedForDelegation: ["fixture-host"] },
  },
  "source:fixture-sqli-rule": {
    issuePresent: true,
    detail: { ruleId: "fixture-sqli-rule", matchedFile: "src/search.ts", snapshotHash: "fixture-snapshot" },
  },
  "container:sha256:fixture-digest": {
    issuePresent: true,
    detail: { digest: "sha256:fixture-digest", package: "log4j-core", version: "2.14.1", cve: "CVE-2021-44228" },
  },
};

export const FIXTURE_SCANNER_RECHECKS: Record<string, ScannerRecheckObservation> = {
  // Synthetic scanner results (§83): the recheck repeats the governed
  // detection template — it extracts nothing and executes nothing.
  "nuclei:sqli-fixture-template": { reproduced: true, evidenceSummary: "governed detection template matched the recorded synthetic SQLi signature again" },
  "nuclei:xss-fixture-template": { reproduced: true, evidenceSummary: "governed detection template matched the recorded synthetic XSS signature again" },
};
