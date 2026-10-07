import { describe, expect, it } from "vitest";
import {
  GreenboneConnector, NessusConnector, SearchSploitAdapter, generateScannerTargets,
  parseGreenboneReport, parseNessusReport,
} from "./scanners";
import { correlateFindings } from "../vuln/correlation";
import type { NormalizedVulnFinding } from "../vuln/types";
import { InMemoryScannerInstanceProvider, type ScannerInstanceRecord } from "../proxy/types";
import type { ScannerTransport } from "../proxy/connector";
import {
  FIXTURE_CVE, FIXTURE_EXPLOIT_DATASET, FIXTURE_HOST, GREENBONE_FIXTURE, NESSUS_FIXTURE, NESSUS_XXE_ATTACK,
} from "./fixtures";

/**
 * Prompt 11 scanner tests (§93–§96, §101): parsers run on recorded
 * fixture exports only. No scanner is contacted; connector tests use a
 * fixture transport that records calls.
 */

describe("Nessus parser (§15/§93)", () => {
  it("normalizes plugin data: CVE/CWE/CVSS/plugin output with severity from the record", () => {
    const report = parseNessusReport(NESSUS_FIXTURE);
    expect(report.scanner).toBe("nessus-professional");
    expect(report.hosts).toEqual([FIXTURE_HOST]);
    expect(report.findings).toHaveLength(2);
    const log4j = report.findings[0]!;
    expect(log4j.cve).toBe(FIXTURE_CVE);
    expect(log4j.cwe).toBe("CWE-502");
    expect(log4j.cvssScore).toBe(10);
    expect(log4j.cvssVersion).toBe("3.1");
    expect(log4j.severity).toBe("CRITICAL");
    expect(log4j.port).toBe(8080);
    expect(log4j.evidenceDetail?.checkId).toBe("155275");
    expect(log4j.remediation).toContain("Upgrade");
    const info = report.findings[1]!;
    expect(info.severity).toBe("INFORMATIONAL");
  });

  it("rejects XXE and malformed documents (§101)", () => {
    expect(() => parseNessusReport(NESSUS_XXE_ATTACK)).toThrow(/DOCTYPE|ENTITY/);
    expect(() => parseNessusReport("<html></html>")).toThrow(/root element/);
    expect(() => parseNessusReport("not xml at all")).toThrow();
  });

  it("caps oversized reports (§76)", () => {
    const huge = `<NessusClientData_v2><Report name="x">${"<ReportHost name=\"h\">".repeat(1)}${"A".repeat(11 * 1024 * 1024)}</Report></NessusClientData_v2>`;
    expect(() => parseNessusReport(huge)).toThrow(/exceeds/);
  });
});

describe("Greenbone parser (§9/§93)", () => {
  it("normalizes NVT results with OID, CVSS and CVE from tags/cve fields", () => {
    const report = parseGreenboneReport(GREENBONE_FIXTURE);
    expect(report.scanner).toBe("greenbone-openvas");
    expect(report.findings).toHaveLength(2);
    const log4j = report.findings[0]!;
    expect(log4j.cve).toBe(FIXTURE_CVE);
    expect(log4j.cvssScore).toBe(10);
    expect(log4j.port).toBe(8080);
    expect(log4j.evidenceDetail?.checkId).toBe("1.3.6.1.4.1.25623.1.0.117987");
    expect(report.findings[1]!.severity).toBe("MEDIUM");
  });

  it("rejects hostile XML (§101)", () => {
    expect(() => parseGreenboneReport(NESSUS_XXE_ATTACK)).toThrow(/DOCTYPE|ENTITY/);
  });
});

describe("scanner correlation (§94/§95)", () => {
  it("Nuclei + Nessus + Greenbone on the same CVE/asset/service merge into ONE canonical finding with 3 sources", () => {
    const nessus = parseNessusReport(NESSUS_FIXTURE).findings[0]!;
    const greenbone = parseGreenboneReport(GREENBONE_FIXTURE).findings[0]!;
    const nuclei: NormalizedVulnFinding = {
      title: "Apache Log4j RCE", description: "nuclei detection", severity: "CRITICAL", confidence: 0.9,
      host: FIXTURE_HOST, port: 8080, cve: FIXTURE_CVE, cwe: "CWE-502", references: [], referencesDetailed: [],
      sourceTool: "nuclei", sourceFingerprint: "nuclei-fp", vulnClass: "GENERIC_VULNERABILITY",
      sourceConfidence: 0.9, signatureFamily: "nuclei-template-cve-2021-44228",
    };
    const { findings, stats } = correlateFindings([nuclei, nessus, greenbone]);
    const canonical = findings.filter((f) => f.finding.cve === FIXTURE_CVE);
    expect(canonical).toHaveLength(1);
    expect(canonical[0]!.sources.map((s) => s.tool).sort()).toEqual(["greenbone-openvas", "nessus-professional", "nuclei"]);
    expect(stats.duplicatesMerged).toBe(2);
  });

  it("the same CVE on a DIFFERENT asset stays a separate instance (§95)", () => {
    const a = parseNessusReport(NESSUS_FIXTURE).findings[0]!;
    const b = { ...a, host: "198.51.100.7", sourceFingerprint: "other" };
    const { findings } = correlateFindings([a, b]);
    expect(findings.filter((f) => f.finding.cve === FIXTURE_CVE)).toHaveLength(2);
  });
});

describe("scope-derived scanner targets (§6/§13)", () => {
  it("generates targets from scope only; wildcards and exclusions never reach the scanner", () => {
    const gen = generateScannerTargets({
      includeHosts: ["192.0.2.10", "*.example.com", "blocked.example.com"],
      excludeHosts: ["blocked.example.com"],
      includeCidrs: ["192.0.2.0/24"], allowedPorts: [], allowedPaths: [], excludedPaths: [],
    });
    expect(gen.targets).toContain("192.0.2.10");
    expect(gen.targets).toContain("192.0.2.0/24");
    expect(gen.targets).not.toContain("blocked.example.com");
    expect(gen.rejected.map((r) => r.value)).toContain("*.example.com");
  });
});

function fixtureTransport(routes: Record<string, { status: number; body: string }>): ScannerTransport & { calls: string[] } {
  const calls: string[] = [];
  return {
    calls,
    async request({ request }) {
      calls.push(`${request.method} ${request.path}`);
      const hit = routes[`${request.method} ${request.path}`] ?? routes[request.path];
      return { status: hit?.status ?? 404, body: hit?.body ?? "", latencyMs: 3 };
    },
  };
}

const instance = (over: Partial<ScannerInstanceRecord> = {}): ScannerInstanceRecord => ({
  id: "inst-1", organizationId: "org-1", toolSlug: "nessus-professional", product: "NESSUS",
  name: "lab nessus", endpointReference: "NESSUS_LAB", deploymentType: "ADMIN_PROVIDED",
  declaredCapabilities: ["VULNERABILITY_SCANNING"], detectedCapabilities: [], enabled: true,
  healthStatus: "NOT_CONFIGURED", createdBy: "admin", createdAt: new Date(0).toISOString(), updatedAt: new Date(0).toISOString(),
  licenseState: "LICENSED",
  ...over,
} as unknown as ScannerInstanceRecord);

describe("connectors (§3–§14, §85)", () => {
  const endpoints = { resolve: async (ref: string) => (ref === "NESSUS_LAB" || ref === "GB_LAB" ? { baseUrl: "https://scanner.lab.example:8834", approvedInternal: true } : undefined) };
  const secrets = { resolve: async () => "fixture-secret" };

  it("Nessus health reads version + license from the deployment; unconfigured endpoint is MISCONFIGURED", async () => {
    const transport = fixtureTransport({ "GET /server/status": { status: 200, body: JSON.stringify({ version: "10.8.0", feedStatus: "CURRENT" }) } });
    const connector = new NessusConnector(transport, endpoints, secrets);
    const health = await connector.healthCheck(instance());
    expect(health.status).toBe("HEALTHY");
    expect(health.version).toBe("10.8.0");
    expect(health.licenseState).toBe("LICENSED");
    const missing = await connector.healthCheck(instance({ endpointReference: "NOPE" }));
    expect(missing.status).toBe("MISCONFIGURED");
    void InMemoryScannerInstanceProvider;
  });

  it("logical profiles resolve only through administrator mappings; scan creation refuses unmapped profiles", async () => {
    const transport = fixtureTransport({ "POST /scans": { status: 200, body: JSON.stringify({ id: "task-9" }) } });
    const connector = new NessusConnector(transport, endpoints, secrets);
    const withConfig = instance();
    (withConfig as unknown as { config: unknown }).config = { profiles: { NETWORK_BASELINE: "policy-42" } };
    expect(connector.resolveProfile(withConfig, "NETWORK_BASELINE")).toBe("policy-42");
    expect(connector.resolveProfile(withConfig, "NETWORK_COMPREHENSIVE")).toBeUndefined();
    await expect(connector.createScan(withConfig, { logicalProfile: "NETWORK_COMPREHENSIVE", targets: ["192.0.2.10"], name: "x" })).rejects.toThrow(/not mapped/);
    const created = await connector.createScan(withConfig, { logicalProfile: "NETWORK_BASELINE", targets: ["192.0.2.10"], name: "baseline" });
    expect(created.scannerTaskId).toBe("task-9");
    // The raw scanner policy id came from admin config — the caller only ever named the logical profile.
    expect(transport.calls).toContain("POST /scans");
  });

  it("Greenbone health reports DEGRADED on a stale feed", async () => {
    const transport = fixtureTransport({ "GET /health": { status: 200, body: JSON.stringify({ version: "22.4", feedStatus: "STALE" }) } });
    const connector = new GreenboneConnector(transport, endpoints, secrets);
    const gb = instance({ toolSlug: "greenbone-openvas", product: "GREENBONE", endpointReference: "GB_LAB" });
    const health = await connector.healthCheck(gb);
    expect(health.status).toBe("DEGRADED");
    expect(health.version).toBe("22.4");
  });

  it("fetchReport parses through the product parser", async () => {
    const transport = fixtureTransport({ "GET /scans/task-9/report": { status: 200, body: NESSUS_FIXTURE } });
    const connector = new NessusConnector(transport, endpoints, secrets);
    const report = await connector.fetchReport(instance(), "task-9");
    expect(report.findings).toHaveLength(2);
  });
});

describe("SearchSploit reference adapter (§17–§21)", () => {
  it("looks up references by CVE first; capability is lookup-only", () => {
    const adapter = new SearchSploitAdapter(FIXTURE_EXPLOIT_DATASET);
    expect(adapter.capability).toBe("VULNERABILITY_REFERENCE_LOOKUP");
    const hits = adapter.lookup({ cveId: FIXTURE_CVE });
    expect(hits).toHaveLength(1);
    expect(hits[0]!.meaning).toBe("PUBLIC_EXPLOIT_REFERENCE_EXISTS");
    expect(hits[0]!.externalId).toBe("50592");
  });

  it("the shipped empty dataset reports nothing — no invented references", () => {
    const adapter = new SearchSploitAdapter();
    expect(adapter.lookup({ cveId: FIXTURE_CVE })).toEqual([]);
    expect(adapter.lookup({ product: "Apache Log4j2" })).toEqual([]);
  });
});
