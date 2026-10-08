/**
 * Recorded fixture feeds (Prompt 30 verification).
 *
 * These are SMALL EXCERPTS in the real provider formats (NVD API 2.0,
 * FIRST EPSS CSV, CISA KEV JSON, OSV/GHSA), used only by tests and by
 * explicitly-labelled smoke imports. They are never seeded into the
 * shipped dataset: the production intelligence tables stay EMPTY /
 * NEVER_SYNCED until a governed sync or import actually happens, and
 * every import of these documents is provenance-labelled FIXTURE.
 */

export const FIXTURE_SOURCE = "FIXTURE";

/** NVD 2.0 excerpt: Log4Shell (branch ranges), HTTP/2 Rapid Reset, one
 *  rejected CVE, one malformed id (must be rejected by the parser). */
export const NVD_FIXTURE_FEED = JSON.stringify({
  resultsPerPage: 4, startIndex: 0, totalResults: 4,
  vulnerabilities: [
    {
      cve: {
        id: "CVE-2021-44228",
        sourceIdentifier: "nvd@nist.gov",
        published: "2021-12-10T10:15:00.000",
        lastModified: "2023-11-07T03:00:00.000",
        vulnStatus: "Modified",
        descriptions: [{ lang: "en", value: "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.4 and 2.3.2) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints." }],
        metrics: {
          cvssMetricV31: [{ source: "nvd@nist.gov", type: "Primary", cvssData: { version: "3.1", vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", baseScore: 10.0, baseSeverity: "CRITICAL" } }],
        },
        weaknesses: [{ source: "nvd@nist.gov", type: "Primary", description: [{ lang: "en", value: "CWE-917" }] }],
        references: [{ url: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", source: "nvd@nist.gov" }],
        configurations: [{
          nodes: [{
            operator: "OR", negate: false,
            cpeMatch: [
              { vulnerable: true, criteria: "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", versionStartIncluding: "2.0.0", versionEndExcluding: "2.12.2", criteriaDetail: "branch 2.12.x" },
              { vulnerable: true, criteria: "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*", versionStartIncluding: "2.13.0", versionEndExcluding: "2.15.0", criteriaDetail: "branch 2.13+" },
            ],
          }],
        }],
      },
    },
    {
      cve: {
        id: "CVE-2023-44487",
        sourceIdentifier: "nvd@nist.gov",
        published: "2023-10-10T14:15:00.000",
        lastModified: "2024-01-01T00:00:00.000",
        vulnStatus: "Analyzed",
        descriptions: [{ lang: "en", value: "The HTTP/2 protocol allows a denial of service (server resource consumption) because request cancellation can reset many streams quickly, as exploited in the wild in August through October 2023." }],
        metrics: {
          cvssMetricV31: [{ source: "nvd@nist.gov", type: "Primary", cvssData: { version: "3.1", vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", baseScore: 7.5, baseSeverity: "HIGH" } }],
        },
        weaknesses: [{ source: "nvd@nist.gov", type: "Primary", description: [{ lang: "en", value: "CWE-400" }] }],
        references: [{ url: "https://nvd.nist.gov/vuln/detail/CVE-2023-44487", source: "nvd@nist.gov" }],
        configurations: [{
          nodes: [{
            operator: "OR", negate: false,
            cpeMatch: [
              { vulnerable: true, criteria: "cpe:2.3:a:ietf:http:*:*:*:*:*:*:*:*", versionStartIncluding: "2.0", criteriaDetail: "protocol" },
            ],
          }],
        }],
      },
    },
    {
      cve: {
        id: "CVE-2024-3094",
        sourceIdentifier: "nvd@nist.gov",
        published: "2024-03-29T16:15:00.000",
        lastModified: "2024-04-02T00:00:00.000",
        vulnStatus: "Rejected",
        descriptions: [{ lang: "en", value: "Rejected reason: DO NOT USE THIS CVE RECORD. (Fixture excerpt modelling a withdrawn record.)" }],
        metrics: {},
        weaknesses: [],
        references: [],
        configurations: [],
      },
    },
    {
      cve: {
        id: "CVE-24-123",
        sourceIdentifier: "nvd@nist.gov",
        published: "2024-01-01T00:00:00.000",
        vulnStatus: "Analyzed",
        descriptions: [{ lang: "en", value: "Malformed identifier entry — the parser must reject this record (§131)." }],
        metrics: {}, weaknesses: [], references: [], configurations: [],
      },
    },
  ],
});

/** Same CVE scored differently by a second trusted source (§132/§69). */
export const NVD_FIXTURE_FEED_SECOND_SOURCE = JSON.stringify({
  resultsPerPage: 1, startIndex: 0, totalResults: 1,
  vulnerabilities: [{
    cve: {
      id: "CVE-2021-44228",
      sourceIdentifier: "cna@example.org",
      published: "2021-12-10T10:15:00.000",
      lastModified: "2021-12-14T00:00:00.000",
      vulnStatus: "Published",
      descriptions: [{ lang: "en", value: "Second-source description of the Log4j JNDI issue (fixture)." }],
      metrics: {
        cvssMetricV31: [{ source: "cna@example.org", type: "Secondary", cvssData: { version: "3.1", vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", baseScore: 9.3, baseSeverity: "CRITICAL" } }],
      },
      weaknesses: [{ source: "cna@example.org", type: "Secondary", description: [{ lang: "en", value: "CWE-20" }] }],
      references: [],
      configurations: [],
    },
  }],
});

/** EPSS CSV excerpts for two dates — history must retain both (§133). */
export const EPSS_FIXTURE_CSV_DAY1 = [
  "#model_version:v2023.03.01,score_date:2026-10-01T00:00:00Z",
  "cve,epss,percentile",
  "CVE-2021-44228,0.94300,0.99900",
  "CVE-2023-44487,0.12000,0.87000",
].join("\n");

export const EPSS_FIXTURE_CSV_DAY2 = [
  "#model_version:v2023.03.01,score_date:2026-10-07T00:00:00Z",
  "cve,epss,percentile",
  "CVE-2021-44228,0.97500,0.99950",
  "CVE-2023-44487,0.64000,0.98500",
].join("\n");

/** KEV catalog excerpt. 44487 is added by the SECOND excerpt (§134). */
export const KEV_FIXTURE_CATALOG_1 = JSON.stringify({
  title: "Known Exploited Vulnerabilities Catalog (fixture excerpt)",
  catalogVersion: "fixture-1",
  count: 1,
  vulnerabilities: [{
    cveID: "CVE-2021-44228", vendorProject: "Apache", product: "Log4j2",
    vulnerabilityName: "Apache Log4j2 Remote Code Execution Vulnerability",
    dateAdded: "2021-12-10", requiredAction: "Apply updates per vendor instructions.",
    dueDate: "2021-12-24", knownRansomwareCampaignUse: "Known", notes: "Fixture excerpt.",
  }],
});

export const KEV_FIXTURE_CATALOG_2 = JSON.stringify({
  title: "Known Exploited Vulnerabilities Catalog (fixture excerpt)",
  catalogVersion: "fixture-2",
  count: 2,
  vulnerabilities: [
    {
      cveID: "CVE-2021-44228", vendorProject: "Apache", product: "Log4j2",
      vulnerabilityName: "Apache Log4j2 Remote Code Execution Vulnerability",
      dateAdded: "2021-12-10", requiredAction: "Apply updates per vendor instructions.",
      dueDate: "2021-12-24", knownRansomwareCampaignUse: "Known", notes: "Fixture excerpt.",
    },
    {
      cveID: "CVE-2023-44487", vendorProject: "IETF", product: "HTTP/2",
      vulnerabilityName: "HTTP/2 Rapid Reset Attack Vulnerability",
      dateAdded: "2023-10-10", requiredAction: "Apply mitigations per vendor instructions.",
      dueDate: "2023-10-31", knownRansomwareCampaignUse: "Unknown", notes: "Fixture excerpt.",
    },
  ],
});

/** GHSA/OSV advisory excerpt: fixed versions for log4j-core (§142),
 *  plus a mitigation-only record with NO fixed version (§143). */
export const ADVISORY_FIXTURE = JSON.stringify([
  {
    id: "GHSA-jfh8-c2jp-5v3q",
    summary: "Remote code execution in Apache Log4j2",
    details: "Apache Log4j2 vulnerable to RCE via JNDI. Fixed versions are published per branch.",
    aliases: ["CVE-2021-44228"],
    published: "2021-12-10T00:00:00Z",
    modified: "2021-12-14T00:00:00Z",
    references: [{ type: "WEB", url: "https://github.com/advisories/GHSA-jfh8-c2jp-5v3q" }],
    affected: [{
      package: { ecosystem: "Maven", name: "org.apache.logging.log4j:log4j-core" },
      ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "2.13.0" }, { fixed: "2.15.0" }] }],
    }],
  },
  {
    id: "GHSA-fixture-nofix",
    summary: "HTTP/2 rapid reset — mitigation guidance only (fixture)",
    details: "Vendors recommend mitigation via rate limiting and stream reset controls; no single fixed version is published in this fixture record.",
    aliases: ["CVE-2023-44487"],
    published: "2023-10-10T00:00:00Z",
    modified: "2023-10-11T00:00:00Z",
    references: [{ type: "WEB", url: "https://example.com/advisories/rapid-reset" }],
    affected: [{
      package: { ecosystem: "generic", name: "http2" },
      ranges: [{ type: "ECOSYSTEM", events: [{ introduced: "2.0" }] }],
    }],
  },
]);

/** Malicious provider payload (§153/§154): HTML/control chars in text and
 *  a private/loopback reference URL. The private URL is a validated
 *  http URL so it IS stored as a reference string — but nothing in the
 *  platform ever fetches it; the test asserts no fetch surface exists. */
export const NVD_FIXTURE_MALICIOUS = JSON.stringify({
  vulnerabilities: [{
    cve: {
      id: "CVE-2023-44487",
      sourceIdentifier: "nvd@nist.gov",
      published: "2023-10-10T14:15:00.000",
      vulnStatus: "Analyzed",
      descriptions: [{ lang: "en", value: "Reset <script>alert(1)</script> flood\u0007 with control chars" }],
      metrics: {},
      weaknesses: [],
      references: [
        { url: "javascript:alert(1)", source: "attacker" },
        { url: "http://169.254.169.254/latest/meta-data/", source: "attacker" },
        { url: "https://example.com/legit-reference", source: "vendor" },
      ],
      configurations: [],
    },
  }],
});
