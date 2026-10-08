/**
 * Recorded fixtures for Network VAPT V2 (Prompt 33).
 *
 * Documentation ranges only (192.0.2.0/24, 203.0.113.0/24 — RFC 5737)
 * and example.com hostnames. Nothing here was produced by scanning a
 * real network: each artifact is a hand-authored recording in the real
 * tool's output format, so parsers, normalization, correlation and the
 * API can be verified with zero network access. The Nessus fixture
 * deliberately contains a SYNTHETIC scanner secret string (a fake value
 * that is not, and never was, a real credential) so the §143 redaction
 * tests can prove it never survives normalization.
 */
import type { TlsServiceEvidence } from "./protocols";
import type { HostPostureSnapshot } from "./drift";
import type { TsharkProtocolRecord } from "./packet";

/** The synthetic secret planted in the Nessus fixture (§143). FAKE. */
export const SYNTHETIC_SCANNER_SECRET = "SYNTH-NESSUS-KEY-0000-TESTONLY";

/** Nessus .nessus excerpt: CVE-2021-41773 against the Apache 2.4.49
 *  service the Prompt 10 Nmap fixture records on 192.0.2.10:80, plus an
 *  informational plugin whose output carries the synthetic secret. */
export const NESSUS_V2_XML = `<?xml version="1.0" encoding="UTF-8"?>
<NessusClientData_v2>
<Report name="fixture-network-v2">
<ReportHost name="192.0.2.10">
<ReportItem port="80" svc_name="www" protocol="tcp" severity="4" pluginID="154832" pluginName="Apache 2.4.49 Path Traversal" pluginFamily="Web Servers">
<description>The remote Apache httpd is 2.4.49 and is affected by CVE-2021-41773, a path traversal vulnerability in mod_alias.</description>
<solution>Upgrade to Apache httpd 2.4.51 or later.</solution>
<plugin_output>Apache/2.4.49 (Unix) banner confirmed on 192.0.2.10:80.</plugin_output>
<cve>CVE-2021-41773</cve>
<cvss_base_score>9.8</cvss_base_score>
<risk_factor>Critical</risk_factor>
<see_also>https://nvd.nist.gov/vuln/detail/CVE-2021-41773</see_also>
</ReportItem>
<ReportItem port="443" svc_name="https" protocol="tcp" severity="0" pluginID="900001" pluginName="Scanner Connectivity Note" pluginFamily="Settings">
<description>Informational note recorded by the scanner during the fixture run.</description>
<plugin_output>Authenticated with api_key=${SYNTHETIC_SCANNER_SECRET} against the scanner console; session closed.</plugin_output>
<risk_factor>None</risk_factor>
</ReportItem>
</ReportHost>
</Report>
</NessusClientData_v2>`;

/** Greenbone/OpenVAS GMP excerpt reporting the SAME CVE on the SAME
 *  host/port with a DIFFERENT severity (7.5 HIGH vs Nessus CRITICAL) —
 *  the §146/§70 dedup + disagreement fixture. */
export const GREENBONE_V2_XML = `<?xml version="1.0" encoding="UTF-8"?>
<get_reports_response status="200" status_text="OK">
<report>
<report>
<results>
<result>
<name>Apache HTTP Server Path Traversal (CVE-2021-41773)</name>
<host>192.0.2.10</host>
<port>80/tcp</port>
<severity>7.5</severity>
<description>The Apache HTTP Server 2.4.49 is vulnerable to CVE-2021-41773 path traversal via mod_alias normalization.</description>
<nvt oid="1.3.6.1.4.1.25623.1.0.900001">
<name>Apache HTTP Server Path Traversal</name>
<family>Web application abuses</family>
<cve>CVE-2021-41773</cve>
<cvss_base>7.5</cvss_base>
</nvt>
</result>
</results>
</report>
</report>
</get_reports_response>`;

/** testssl-style TLS evidence (§53/§54): TLSv1.0 + a weak cipher + an
 *  expired certificate on a documentation-range host. */
export const TLS_V2_EVIDENCE: TlsServiceEvidence[] = [
  {
    host: "203.0.113.20", port: 443, source: "testssl",
    protocolVersions: ["TLSv1.0", "TLSv1.2", "TLSv1.3"],
    weakCiphers: ["TLS_RSA_WITH_3DES_EDE_CBC_SHA"],
    certificate: { expired: true, hostnameMismatch: false, chainIssues: [], notAfter: "2025-01-15T00:00:00Z", subject: "CN=legacy.example.com" },
  },
  {
    host: "203.0.113.21", port: 443, source: "sslyze",
    protocolVersions: ["TLSv1.2", "TLSv1.3"], weakCiphers: [],
    certificate: { expired: false, hostnameMismatch: true, chainIssues: ["unable to get local issuer certificate"], subject: "CN=other.example.com" },
  },
];

/** ssh2-enum-algos style evidence with legacy algorithms (§46). */
export const SSH_V2_EVIDENCE = {
  host: "192.0.2.10", port: 22,
  banner: "SSH-2.0-OpenSSH_8.9p1",
  protocolVersion: "2.0",
  algorithms: ["curve25519-sha256", "diffie-hellman-group14-sha256", "3des-cbc", "hmac-sha1-96", "ssh-rsa", "aes256-ctr"],
};

/** tshark-style protocol metadata (§91): one cleartext flow, one weak
 *  TLS flow, one DNS NXDOMAIN, one unexpected service flow. */
export const TSHARK_V2_RECORDS: TsharkProtocolRecord[] = [
  { frameProtocol: "telnet", sourceIp: "198.51.100.7", destIp: "203.0.113.20", destPort: 23 },
  { frameProtocol: "tls", sourceIp: "198.51.100.7", destIp: "203.0.113.20", destPort: 443, tlsVersion: "TLSv1.0" },
  { frameProtocol: "dns", sourceIp: "198.51.100.7", destIp: "203.0.113.1", destPort: 53, dnsQuery: "gone.example.com", dnsResponseCode: "NXDOMAIN" },
  { frameProtocol: "tcp", sourceIp: "198.51.100.7", destIp: "203.0.113.20", destPort: 6379 },
];

/** §153 drift fixture: baseline {22, 443} → current {22, 443, 3389} on
 *  a CRITICAL production host. */
export const DRIFT_BASELINE_HOST: HostPostureSnapshot = {
  host: "192.0.2.30", criticality: "CRITICAL", environment: "PRODUCTION",
  services: [
    { port: 22, transport: "tcp", service: "ssh", version: "8.9p1", tls: false },
    { port: 443, transport: "tcp", service: "https", version: "1.25.3", tls: true },
  ],
  vulnerabilities: [],
};

export const DRIFT_CURRENT_HOST: HostPostureSnapshot = {
  host: "192.0.2.30", criticality: "CRITICAL", environment: "PRODUCTION",
  services: [
    { port: 22, transport: "tcp", service: "ssh", version: "8.9p1", tls: false },
    { port: 443, transport: "tcp", service: "https", version: "1.25.3", tls: true },
    { port: 3389, transport: "tcp", service: "ms-wbt-server", tls: false },
  ],
  vulnerabilities: [],
};

/** Weak-banner service for §147: a product guessed from a thin banner. */
export const WEAK_BANNER_SERVICE = {
  host: "192.0.2.40", port: 8080, protocol: "tcp", name: "http",
  product: "Apache httpd", version: "2.4.49", confidence: 0.3,
};
