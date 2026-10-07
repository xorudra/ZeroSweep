import type { ExploitReferenceDataset, ExploitReferenceRecord } from "./scanners";

/**
 * Controlled-lab fixtures (Prompt 11 §93): recorded scanner exports and
 * intelligence payloads over RFC 5737 documentation addresses only.
 * CVE-2021-44228 (Log4Shell) is used because it is real, KEV-listed and
 * unambiguous — the fixture DATA is recorded, the values are the public
 * record, and nothing here was fetched live.
 */

export const FIXTURE_CVE = "CVE-2021-44228";
export const FIXTURE_HOST = "192.0.2.10";

export const NESSUS_FIXTURE = `<?xml version="1.0"?>
<NessusClientData_v2>
<Report name="fixture-network-baseline">
<ReportHost name="${FIXTURE_HOST}">
<HostProperties><tag name="host-ip">${FIXTURE_HOST}</tag></HostProperties>
<ReportItem port="8080" svc_name="www" protocol="tcp" severity="4" pluginID="155275" pluginName="Apache Log4j Unsupported Version Detection" pluginFamily="Misc.">
<risk_factor>Critical</risk_factor>
<description>The remote host is running Apache Log4j, a Java logging library that is no longer supported and is affected by CVE-2021-44228.</description>
<solution>Upgrade to a supported version of Apache Log4j.</solution>
<cvss_base_score>10.0</cvss_base_score>
<cvss_vector>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H</cvss_vector>
<cve>CVE-2021-44228</cve>
<cwe>502</cwe>
<cpe>cpe:/a:apache:log4j:2.14.1</cpe>
<see_also>https://nvd.nist.gov/vuln/detail/CVE-2021-44228</see_also>
<plugin_output>Path : /opt/app/lib/log4j-core-2.14.1.jar
Installed version : 2.14.1</plugin_output>
</ReportItem>
<ReportItem port="443" svc_name="www" protocol="tcp" severity="0" pluginID="10107" pluginName="HTTP Server Type and Version" pluginFamily="Web Servers">
<risk_factor>None</risk_factor>
<description>The remote web server type is : Apache/2.4.49</description>
<solution>n/a</solution>
<plugin_output>The remote web server type is : Apache/2.4.49</plugin_output>
</ReportItem>
</ReportHost>
</Report>
</NessusClientData_v2>`;

export const GREENBONE_FIXTURE = `<?xml version="1.0"?>
<get_reports_response status="200">
<report>
<report format="XML">
<results>
<result id="r-1">
<name>Apache Log4j Remote Code Execution (Log4Shell)</name>
<host>${FIXTURE_HOST}</host>
<port>8080/tcp</port>
<severity>10.0</severity>
<description>The remote Apache Log4j is vulnerable to CVE-2021-44228 (Log4Shell).</description>
<nvt oid="1.3.6.1.4.1.25623.1.0.117987">
<name>Apache Log4j Remote Code Execution (Log4Shell)</name>
<family>Web application abuses</family>
<cvss_base>10.0</cvss_base>
<cve>CVE-2021-44228</cve>
<tags>cvss_base_vector=CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H</tags>
</nvt>
</result>
<result id="r-2">
<name>SSL/TLS: Report Weak Cipher Suites</name>
<host>${FIXTURE_HOST}</host>
<port>443/tcp</port>
<severity>4.3</severity>
<description>The remote service supports weak cipher suites.</description>
<nvt oid="1.3.6.1.4.1.25623.1.0.105885">
<name>SSL/TLS: Report Weak Cipher Suites</name>
<family>SSL and TLS</family>
<cvss_base>4.3</cvss_base>
</nvt>
</result>
</results>
</report>
</report>
</get_reports_response>`;

export const NVD_FIXTURE = JSON.stringify({
  vulnerabilities: [{
    cve: {
      id: FIXTURE_CVE,
      descriptions: [{ lang: "en", value: "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints." }],
      published: "2021-12-10T10:15:09.143",
      lastModified: "2024-01-01T00:00:00.000",
      metrics: {
        cvssMetricV31: [{ cvssData: { version: "3.1", baseScore: 10.0, vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" } }],
      },
      weaknesses: [{ description: [{ lang: "en", value: "CWE-502" }] }],
      references: [{ url: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228", source: "NVD" }],
    },
  }],
});

export const EPSS_FIXTURE = JSON.stringify({
  data: [{ cve: FIXTURE_CVE, epss: "0.94358", percentile: "0.99913", date: "2026-10-01" }],
});

export const KEV_FIXTURE = JSON.stringify({
  vulnerabilities: [{
    cveID: FIXTURE_CVE,
    vendorProject: "Apache",
    product: "Log4j2",
    vulnerabilityName: "Apache Log4j2 Remote Code Execution Vulnerability",
    dateAdded: "2021-12-10",
    requiredAction: "Apply updates per vendor instructions.",
    dueDate: "2021-12-24",
    knownRansomwareCampaignUse: "Known",
  }],
});

const EXPLOIT_RECORDS: ExploitReferenceRecord[] = [{
  externalId: "50592",
  title: "Apache Log4j2 2.14.1 - Remote Code Execution (RCE)",
  reference: "https://www.exploit-db.com/exploits/50592",
  platform: "Java",
  type: "webapps",
  cveIds: [FIXTURE_CVE],
  product: "Apache Log4j2",
}];

/** Fixture Exploit-DB reference dataset (§93): controlled identifiers only. */
export const FIXTURE_EXPLOIT_DATASET: ExploitReferenceDataset = {
  lookupByCve: (cveId) => EXPLOIT_RECORDS.filter((r) => r.cveIds.includes(cveId)),
  lookupByProduct: (product) => EXPLOIT_RECORDS.filter((r) => (r.product ?? "").toLowerCase().includes(product.toLowerCase())),
};

export const NESSUS_XXE_ATTACK = `<?xml version="1.0"?>
<!DOCTYPE NessusClientData_v2 [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<NessusClientData_v2><Report name="x"><ReportHost name="192.0.2.10"></ReportHost></Report></NessusClientData_v2>`;
