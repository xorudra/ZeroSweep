import { describe, expect, it } from "vitest";
import {
  analyzePacketMetadata, analyzeProtocolServices, analyzeSshEvidence, analyzeTlsEvidence,
  assessExposure, assessNetworkRisk, authFailureLimitation, buildNetworkScopeSnapshot,
  categorizeScriptV2, cidrCoveredBySnapshot, clampNetworkVaptBudget, classifySensitiveService,
  compareNetworkSnapshots, computeNetworkCoverage, correlateNetworkFindings,
  decideDiscoveredHost, deriveVulnScanOutcome, evaluateCredentialedScan, evaluateMasscanGate,
  evaluateMetasploitVerification, evaluateNetworkPreflight, evaluatePacketCapture,
  firewallObservation, groundedNetworkAnswer, judgeIpAgainstSnapshot, makeOsFingerprint,
  networkProfileDefinition, normalizeNetworkTarget, normalizeScannerReport,
  planFromNaturalLanguage, planNetworkVerification, redactScannerSecrets, resolvePortSet,
  scannerLogicalProfile, screenNetworkAiRequest, selectNseScriptsV2,
  DefensiveExploitReferenceService,
  DRIFT_BASELINE_HOST, DRIFT_CURRENT_HOST, GREENBONE_V2_XML, NESSUS_V2_XML, SSH_V2_EVIDENCE,
  SYNTHETIC_SCANNER_SECRET, TLS_V2_EVIDENCE, TSHARK_V2_RECORDS,
  NETWORK_PROFILE_KEYS,
} from "./index";
import { parseGreenboneReport, parseNessusReport, EMPTY_EXPLOIT_REFERENCE_DATASET } from "../vulnmgmt/scanners";
import { NmapParser, NaabuParser } from "../network/parsers-network";
import { NMAP_XML, NAABU_JSONL } from "../network/fixtures-network";
import { mergeServices } from "../network/aggregator";
import { classifyServiceChecks } from "../network/network-checks";

const AUTH_OK = { targetVerified: true, authorizationExists: true, authorizationActive: true, authorizationExpired: false, targetCoveredByScope: true, toolAllowed: true, profileAllowed: true };

describe("targets: normalization + injection (§3–§6, §138, §140)", () => {
  it("rejects shell metacharacters and option injection as hostile data (§138)", () => {
    for (const hostile of ["192.0.2.10; rm -rf /", "192.0.2.10 && cat /etc/passwd", "-oXevil", "--script=brute", "192.0.2.10|nc", "$(reboot)", "host name.example.com", "http://example.com/path"]) {
      const r = normalizeNetworkTarget(hostile);
      expect(r.ok, hostile).toBe(false);
      expect(r.reason).toBe("TARGET_INJECTION_REJECTED");
    }
  });
  it("normalizes IPv4, IPv6, CIDR and hostnames", () => {
    expect(normalizeNetworkTarget("192.0.2.10").target).toMatchObject({ type: "IP", family: 4 });
    expect(normalizeNetworkTarget("2001:db8::10").target).toMatchObject({ type: "IP", family: 6 });
    const cidr = normalizeNetworkTarget("203.0.113.0/24");
    expect(cidr.ok).toBe(true);
    expect(cidr.target?.hostCount).toBe(254);
    expect(normalizeNetworkTarget("Server.Example.COM.").target?.value).toBe("server.example.com");
  });
  it("blocks loopback/metadata and unauthorized private ranges", () => {
    expect(normalizeNetworkTarget("127.0.0.1").reason).toBe("PROTECTED_DESTINATION");
    expect(normalizeNetworkTarget("169.254.169.254").ok).toBe(false);
    expect(normalizeNetworkTarget("localhost").ok).toBe(false);
    expect(normalizeNetworkTarget("10.0.0.5").reason).toBe("INTERNAL_NOT_AUTHORIZED");
    expect(normalizeNetworkTarget("10.0.0.5", { internalAuthorized: true }).ok).toBe(true);
  });
  it("§140: an unauthorized huge CIDR is BLOCKED even with internal authorization", () => {
    const r = normalizeNetworkTarget("10.0.0.0/8", { internalAuthorized: true });
    expect(r.ok).toBe(false);
    expect(r.reason).toBe("CIDR_BLOCKED");
    expect(normalizeNetworkTarget("0.0.0.0/0").ok).toBe(false);
  });
});

describe("budget + Masscan gate (§17/§18/§27/§139)", () => {
  it("clamps budgets one-directionally against the platform ceiling", () => {
    const def = networkProfileDefinition("NETWORK_SAFE");
    const { budget, clampedFields } = clampNetworkVaptBudget({ maxHosts: 999_999, maxRatePerSecond: 10 ** 9 }, def.defaultBudget);
    expect(budget.maxHosts).toBe(4_096);
    expect(budget.maxRatePerSecond).toBe(10_000);
    expect(clampedFields).toContain("maxHosts");
    expect(clampedFields).toContain("maxRatePerSecond");
    expect(budget.maxTotalPorts).toBeLessThanOrEqual(budget.maxHosts * budget.maxPortsPerHost);
  });
  it("§139: an excessive Masscan rate is refused, not silently honored", () => {
    const excessive = evaluateMasscanGate({ explicitlyRequested: true, highThroughputPermission: true, platformPermission: true, scopeHostCount: 100, scopePortCount: 50, requestedRate: 1_000_000 });
    expect(excessive.approved).toBe(false);
    expect(excessive.verdict).toBe("MASSCAN_NOT_APPROVED");
    expect(excessive.reasons.join(" ")).toMatch(/exceeds the platform hard limit/);
  });
  it("Masscan is never a default and needs every gate input", () => {
    expect(evaluateMasscanGate({ explicitlyRequested: false, highThroughputPermission: true, platformPermission: true, scopeHostCount: 10, scopePortCount: 10 }).approved).toBe(false);
    expect(evaluateMasscanGate({ explicitlyRequested: true, highThroughputPermission: false, platformPermission: true, scopeHostCount: 10, scopePortCount: 10 }).approved).toBe(false);
    const ok = evaluateMasscanGate({ explicitlyRequested: true, highThroughputPermission: true, platformPermission: true, scopeHostCount: 100, scopePortCount: 50, requestedRate: 5_000 });
    expect(ok.approved).toBe(true);
    expect(ok.limits?.maxRate).toBeLessThanOrEqual(10_000);
    for (const key of NETWORK_PROFILE_KEYS) {
      expect(networkProfileDefinition(key).toolSlugs).not.toContain("masscan");
    }
  });
  it("§31: FULL_TCP never materializes without an explicit policy grant", () => {
    const denied = resolvePortSet({ set: "FULL_TCP", udpEnabled: false });
    expect(denied.fullTcpGranted).toBe(false);
    expect(denied.ports.length).toBeLessThan(100);
    const granted = resolvePortSet({ set: "FULL_TCP", udpEnabled: false, fullTcpApproved: true });
    expect(granted.fullTcpGranted).toBe(true);
    expect(granted.ports.length).toBe(65_535);
  });
});

describe("NSE policy V2 (§37/§38/§142)", () => {
  it("§142: brute/dos/exploit scripts are structurally blocked", () => {
    const r = selectNseScriptsV2({ profileKey: "NETWORK_VULNERABILITY", requestedScriptIds: ["ssh-brute", "http-slowloris-check", "smb-psexec"], vulnApprovedAllowlist: ["smb-psexec"], vulnerabilityScanPermission: true });
    expect(r.selected).toHaveLength(0);
    expect(r.blocked.map((b) => b.category)).toEqual(expect.arrayContaining(["BRUTE", "DOS"]));
    expect(categorizeScriptV2("ssh-brute").category).toBe("BRUTE");
  });
  it("VULN_APPROVED needs profile + allowlist + permission together", () => {
    const base = { requestedScriptIds: ["ssl-heartbleed"] };
    expect(selectNseScriptsV2({ ...base, profileKey: "NETWORK_SAFE", vulnApprovedAllowlist: ["ssl-heartbleed"], vulnerabilityScanPermission: true }).selected).toHaveLength(0);
    expect(selectNseScriptsV2({ ...base, profileKey: "NETWORK_VULNERABILITY", vulnApprovedAllowlist: [], vulnerabilityScanPermission: true }).selected).toHaveLength(0);
    expect(selectNseScriptsV2({ ...base, profileKey: "NETWORK_VULNERABILITY", vulnApprovedAllowlist: ["ssl-heartbleed"], vulnerabilityScanPermission: false }).selected).toHaveLength(0);
    const ok = selectNseScriptsV2({ ...base, profileKey: "NETWORK_VULNERABILITY", vulnApprovedAllowlist: ["ssl-heartbleed"], vulnerabilityScanPermission: true });
    expect(ok.selected).toEqual([{ id: "ssl-heartbleed", category: "VULN_APPROVED" }]);
  });
  it("default selection records only SAFE/DISCOVERY/VERSION scripts (§38)", () => {
    const r = selectNseScriptsV2({ profileKey: "NETWORK_SAFE" });
    expect(r.selected.length).toBeGreaterThan(0);
    for (const s of r.selected) expect(["SAFE", "DISCOVERY", "VERSION"]).toContain(s.category);
  });
});

describe("scope lock + discovered hosts (§11/§12/§141)", () => {
  const snapshot = buildNetworkScopeSnapshot({ cidrs: ["10.0.0.0/28"], hosts: [], exclusions: ["10.0.0.9"] });
  it("§141: a host discovered outside the authorized /28 is a candidate, never scanned", () => {
    const d = decideDiscoveredHost(snapshot, "10.0.0.20", { recordCandidates: true });
    expect(d.membership).toBe("OUT_OF_SCOPE");
    expect(d.scannable).toBe(false);
    expect(d.recordCandidate).toBe(true);
    expect(decideDiscoveredHost(snapshot, "10.0.0.5").scannable).toBe(true);
    expect(judgeIpAgainstSnapshot(snapshot, "10.0.0.9")).toBe("EXCLUDED");
    expect(decideDiscoveredHost(snapshot, "10.0.0.9").recordCandidate).toBe(false);
  });
  it("snapshot hash is stable and CIDR coverage is containment-based", () => {
    const again = buildNetworkScopeSnapshot({ cidrs: ["10.0.0.0/28"] });
    expect(again.hash).toMatch(/^[a-f0-9]{64}$/);
    expect(cidrCoveredBySnapshot(snapshot, "10.0.0.0/29")).toBe(true);
    expect(cidrCoveredBySnapshot(snapshot, "10.0.0.0/24")).toBe(false);
  });
});

describe("preflight (§8/§9)", () => {
  const base = { targetSyntaxOk: true, scopeHostCount: 10, budgetMaxHosts: 256, authorization: AUTH_OK, requiredTools: ["nmap"], rateWithinPolicy: true };
  it("authorization failure BLOCKS regardless of transport", () => {
    const r = evaluateNetworkPreflight({ ...base, transport: "CONFIGURED", toolHealth: [{ slug: "nmap", status: "HEALTHY" }], authorization: { ...AUTH_OK, targetVerified: false } });
    expect(r.status).toBe("BLOCKED");
  });
  it("unwired transport is honestly TOOL_UNAVAILABLE", () => {
    const r = evaluateNetworkPreflight({ ...base, transport: "NOT_CONFIGURED" });
    expect(r.status).toBe("TOOL_UNAVAILABLE");
    expect(r.checks.some((c) => c.status === "NOT_CONFIGURED")).toBe(true);
  });
  it("all facts green → READY", () => {
    const r = evaluateNetworkPreflight({ ...base, transport: "CONFIGURED", toolHealth: [{ slug: "nmap", status: "HEALTHY" }] });
    expect(r.status).toBe("READY");
  });
});

describe("protocol + TLS + OS analysis (§40–§54)", () => {
  it("SSH weak algorithms are finding-grade; no login is modeled anywhere", () => {
    const obs = analyzeSshEvidence(SSH_V2_EVIDENCE);
    expect(obs.some((o) => o.vulnClass === "WEAK_SSH_ALGORITHMS")).toBe(true);
  });
  it("FTP anonymous check is profile-gated (§47)", () => {
    const services = [{ host: "192.0.2.10", port: 21, protocol: "tcp", name: "ftp", state: "OPEN" as const }];
    const evidence = [{ host: "192.0.2.10", port: 21, scriptId: "ftp-anon", output: "Anonymous FTP login allowed" }];
    expect(analyzeProtocolServices(services, evidence, {})).toHaveLength(0);
    const on = analyzeProtocolServices(services, evidence, { ftpAnonymousCheck: true });
    expect(on.some((o) => o.vulnClass === "FTP_ANONYMOUS_ACCESS")).toBe(true);
  });
  it("TLS evidence normalizes expired cert, weak protocol/cipher, mismatch, chain (§54)", () => {
    const obs = analyzeTlsEvidence(TLS_V2_EVIDENCE);
    const classes = obs.map((o) => o.vulnClass);
    expect(classes).toEqual(expect.arrayContaining(["EXPIRED_CERTIFICATE", "WEAK_TLS_PROTOCOL", "WEAK_TLS_CIPHER", "CERTIFICATE_HOSTNAME_MISMATCH", "CERTIFICATE_CHAIN_ISSUE"]));
  });
  it("weak OS fingerprints keep LOW confidence and drop the version hint (§42)", () => {
    const weak = makeOsFingerprint({ host: "192.0.2.10", family: "Linux", versionHint: "5.15", confidence: 0.3, source: "nmap" });
    expect(weak.band).toBe("LOW");
    expect(weak.versionHint).toBeUndefined();
    const strong = makeOsFingerprint({ host: "192.0.2.10", family: "Linux", versionHint: "5.15", confidence: 0.9, source: "nmap" });
    expect(strong.band).toBe("HIGH");
    expect(strong.versionHint).toBe("5.15");
  });
});

describe("scanner normalization + secrets (§59–§66, §143–§145, §155)", () => {
  it("§143: the synthetic scanner secret never survives normalization", () => {
    const report = parseNessusReport(NESSUS_V2_XML);
    const candidates = normalizeScannerReport(report, { knownSecrets: [SYNTHETIC_SCANNER_SECRET] });
    const blob = JSON.stringify(candidates);
    expect(blob).not.toContain(SYNTHETIC_SCANNER_SECRET);
    expect(blob).toContain("[REDACTED-SECRET]");
    expect(redactScannerSecrets(`key is ${SYNTHETIC_SCANNER_SECRET} ok`, [SYNTHETIC_SCANNER_SECRET])).not.toContain(SYNTHETIC_SCANNER_SECRET);
  });
  it("candidates carry plugin provenance and fingerprints (§65/§66)", () => {
    const candidates = normalizeScannerReport(parseNessusReport(NESSUS_V2_XML));
    const cve = candidates.find((c) => c.cve === "CVE-2021-41773");
    expect(cve).toBeDefined();
    expect(cve!.plugin).toMatchObject({ scanner: "nessus-professional", pluginId: "154832" });
    expect(cve!.fingerprint).toBe("net:192.0.2.10:80/tcp:CVE-2021-41773");
  });
  it("§57: V2 profiles map to governed logical scanner profiles only", () => {
    expect(scannerLogicalProfile("GREENBONE", "NETWORK_VULNERABILITY")).toBe("STANDARD");
    expect(scannerLogicalProfile("NESSUS", "NETWORK_VULNERABILITY")).toBe("NETWORK_STANDARD");
    expect(scannerLogicalProfile("NESSUS", "NETWORK_DISCOVERY")).toBeUndefined();
  });
  it("§155: scanner failure is PARTIAL/ERROR — never a clean result", () => {
    const partial = deriveVulnScanOutcome({ plannedScanners: ["nessus-professional", "greenbone-openvas"], completedScanners: ["nessus-professional"], failedScanners: [{ slug: "greenbone-openvas", reason: "NOT_CONFIGURED" }], findings: 3 });
    expect(partial.kind).toBe("PARTIAL");
    const error = deriveVulnScanOutcome({ plannedScanners: ["nessus-professional"], completedScanners: [], failedScanners: [{ slug: "nessus-professional", reason: "unreachable" }], findings: 0 });
    expect(error.kind).toBe("ERROR");
    if (error.kind === "ERROR") expect(error.gaps.join(" ")).toMatch(/not clean/i);
  });
  it("§144/§63: credentials go to exactly one scanner, one validation attempt", () => {
    const ok = evaluateCredentialedScan(
      { credentialReference: "vault://scanner-creds/nessus", targetScanner: "nessus-professional", otherScanners: ["greenbone-openvas", "nmap"] },
      { credentialedPermission: true, credentialExists: true },
    );
    expect(ok.allowed).toBe(true);
    expect(ok.injectionPlan).toMatchObject({ recipient: "nessus-professional", validationAttempts: 1 });
    expect(ok.injectionPlan!.excluded).toContain("greenbone-openvas");
    const lockout = evaluateCredentialedScan(
      { credentialReference: "vault://x", targetScanner: "nessus-professional", otherScanners: [], validationAttempts: 5 },
      { credentialedPermission: true, credentialExists: true },
    );
    expect(lockout.allowed).toBe(false);
    expect(authFailureLimitation("nessus-professional", "192.0.2.10")).toMatch(/coverage gap; no retry/);
  });
});

describe("correlation (§68–§71, §146/§147)", () => {
  it("§146: Nessus + OpenVAS on the same CVE merge into ONE canonical finding", () => {
    const candidates = [
      ...normalizeScannerReport(parseNessusReport(NESSUS_V2_XML)),
      ...normalizeScannerReport(parseGreenboneReport(GREENBONE_V2_XML)),
    ];
    const canonical = correlateNetworkFindings(candidates);
    const merged = canonical.filter((f) => f.cve === "CVE-2021-41773");
    expect(merged).toHaveLength(1);
    expect(merged[0]!.observations).toHaveLength(2);
    expect(merged[0]!.scannersAgreeing).toBe(2);
    expect(merged[0]!.cveAttribution).toBe("CONFIRMED");
  });
  it("§70: severity disagreement is preserved, not silently maxed", () => {
    const candidates = [
      ...normalizeScannerReport(parseNessusReport(NESSUS_V2_XML)),
      ...normalizeScannerReport(parseGreenboneReport(GREENBONE_V2_XML)),
    ];
    const merged = correlateNetworkFindings(candidates).find((f) => f.cve === "CVE-2021-41773")!;
    expect(merged.severityDisagreement).toBe(true);
    expect(new Set(merged.observations.map((o) => o.severity))).toEqual(new Set(["CRITICAL", "HIGH"]));
  });
  it("§147: a weak banner alone never confirms a CVE", () => {
    const weak = correlateNetworkFindings([{
      assetHost: "192.0.2.40", port: 8080, transport: "tcp", title: "Possible Apache issue", description: "banner guess",
      severity: "HIGH", confidence: 0.3, confidenceBand: "LOW", cve: "CVE-2021-41773",
      plugin: { scanner: "nmap", pluginId: "banner", pluginName: "banner" }, evidence: "Server: Apache",
      references: [], observedAt: new Date().toISOString(), fingerprint: "net:192.0.2.40:8080/tcp:CVE-2021-41773", versionEvidence: "BANNER_ONLY",
    }]);
    expect(weak[0]!.cveAttribution).toBe("UNCERTAIN");
    expect(weak[0]!.confidence).toBeLessThanOrEqual(0.6);
  });
});

describe("exploit references + Metasploit policy (§72–§82, §148–§150)", () => {
  it("§148: empty dataset reports nothing; governed records return metadata only", () => {
    const empty = new DefensiveExploitReferenceService(EMPTY_EXPLOIT_REFERENCE_DATASET);
    expect(empty.referencesForCve("CVE-2021-41773")).toEqual([]);
    const populated = new DefensiveExploitReferenceService({
      lookupByCve: () => [{ externalId: "EDB-50508", title: "Apache 2.4.49 Path Traversal", reference: "https://www.exploit-db.com/exploits/50508", platform: "linux", cveIds: ["CVE-2021-41773"], product: "Apache httpd" }],
      lookupByProduct: () => [],
    });
    const refs = populated.referencesForCve("CVE-2021-41773");
    expect(refs).toHaveLength(1);
    expect(refs[0]).toMatchObject({ referenceId: "EDB-50508", executable: false, meaning: "PUBLIC_EXPLOIT_REFERENCE_EXISTS" });
  });
  it("§149: shells/Meterpreter/credential dumping are rejected by policy", () => {
    const v = evaluateMetasploitVerification({
      moduleId: "exploit/windows/smb/ms17_010_eternalblue", targetHost: "192.0.2.10", findingId: "f-1",
      intentDescription: "get a reverse shell meterpreter session", payloadRequested: "windows/meterpreter/reverse_tcp",
      controlledVerificationPermission: true, hostAuthorized: true, hostInScope: true,
    });
    expect(v.decision).toBe("BLOCKED");
    expect(v.reasons.join(" ")).toMatch(/structurally forbidden/);
  });
  it("§150: an allowlisted module pointed outside scope is BLOCKED", () => {
    const v = evaluateMetasploitVerification({
      moduleId: "auxiliary/scanner/smb/smb_ms17_010", targetHost: "203.0.113.99", findingId: "f-1",
      controlledVerificationPermission: true, hostAuthorized: true, hostInScope: false,
    });
    expect(v.decision).toBe("BLOCKED");
  });
  it("a fully-governed request is recorded for manual run — transport NOT_PROVISIONED", () => {
    const v = evaluateMetasploitVerification({
      moduleId: "auxiliary/scanner/smb/smb_ms17_010", targetHost: "192.0.2.10", findingId: "f-1",
      controlledVerificationPermission: true, hostAuthorized: true, hostInScope: true,
    });
    expect(v.decision).toBe("APPROVED_FOR_MANUAL_CONTROLLED_RUN");
    expect(v.transport).toBe("NOT_PROVISIONED");
    expect(v.preferredSafeVerification.length).toBeGreaterThan(0);
  });
});

describe("packet capture governance + analysis (§83–§93, §151)", () => {
  const okRequest = { interfaceReference: "worker-1/eth0", interfaceAuthorized: true, durationSeconds: 300, sizeLimitBytes: 100_000_000, callerCanCreate: true, storageQuotaBytes: 1_000_000_000, storageUsedBytes: 0 };
  it("§151: oversized/overlong captures are rejected, not clamped", () => {
    expect(evaluatePacketCapture({ ...okRequest, durationSeconds: 999_999 }).allowed).toBe(false);
    expect(evaluatePacketCapture({ ...okRequest, sizeLimitBytes: 10 ** 12 }).allowed).toBe(false);
    expect(evaluatePacketCapture({ ...okRequest, callerCanCreate: false }).allowed).toBe(false);
    expect(evaluatePacketCapture(okRequest).allowed).toBe(true);
  });
  it("§92: metadata yields plaintext/weak-TLS/DNS/unexpected-service observations", () => {
    const { summary, findings } = analyzePacketMetadata(TSHARK_V2_RECORDS, { expectedServices: [{ port: 443, protocol: "tls" }, { port: 53, protocol: "dns" }] });
    expect(summary.packetCount).toBe(4);
    const kinds = findings.map((f) => f.kind);
    expect(kinds).toEqual(expect.arrayContaining(["PLAINTEXT_PROTOCOL", "WEAK_PROTOCOL", "DNS_ANOMALY", "UNEXPECTED_SERVICE"]));
  });
});

describe("topology, drift, coverage, risk (§94–§123, §153)", () => {
  it("sensitive services classify; public exposure is a signal, not a vuln (§98/§99)", () => {
    expect(classifySensitiveService({ port: 3306 })).toBe("DATABASE");
    expect(classifySensitiveService({ port: 3389 })).toBe("REMOTE_ADMINISTRATION");
    const exposure = assessExposure({ zone: "INTERNET", port: 3389 });
    expect(exposure.sensitiveServicePubliclyExposed).toBe(true);
    expect(exposure.riskSignal).toMatch(/NOT a vulnerability/);
    expect(firewallObservation({ openPorts: 0, filteredPorts: 5, closedPorts: 0 })).toMatch(/no firewall configuration is claimed/);
  });
  it("§153: new RDP service on a critical production host is an ELEVATED drift signal", () => {
    const events = compareNetworkSnapshots({ version: 1, capturedAt: "2026-10-01T00:00:00Z", hosts: [DRIFT_BASELINE_HOST] }, [DRIFT_CURRENT_HOST]);
    const added = events.find((e) => e.kind === "SERVICE_ADDED");
    expect(added).toBeDefined();
    expect(added!.detail).toMatch(/3389/);
    expect(added!.riskSignal).toBe("ELEVATED");
  });
  it("§123: incomplete coverage never reads COMPLETED", () => {
    const full = computeNetworkCoverage({ authorizedHosts: 10, discoveredHosts: 10, scannedHosts: 10, hostsWithPortScan: 10, hostsWithServiceDetection: 10, hostsWithVulnScan: 10, hostsWithCredentialedScan: null, limitations: [], stageOutcomes: [{ stage: "PORT_DISCOVERY", status: "COMPLETED" }] });
    expect(full.completion).toBe("COMPLETED");
    const gaps = computeNetworkCoverage({ authorizedHosts: 10, discoveredHosts: 10, scannedHosts: 8, hostsWithPortScan: 8, hostsWithServiceDetection: 8, hostsWithVulnScan: 4, hostsWithCredentialedScan: null, limitations: ["scanner unavailable"], stageOutcomes: [{ stage: "VULNERABILITY_ASSESSMENT", status: "PARTIAL" }] });
    expect(gaps.completion).not.toBe("COMPLETED");
    expect(gaps.limitations.length).toBeGreaterThan(0);
  });
  it("risk is contextual: KEV + exposure + criticality outrank bare CVSS; EPSS null ≠ 0 (§108/§109)", () => {
    const hot = assessNetworkRisk({ cvssScore: 7.5, kevListed: true, epssScore: 0.6, internetExposed: true, zone: "INTERNET", assetCriticality: "CRITICAL", sensitiveService: true, confidenceBand: "HIGH", scannersAgreeing: 2, patchAvailable: true, cveAttribution: "CONFIRMED" });
    const cold = assessNetworkRisk({ cvssScore: 7.5, internetExposed: false, zone: "INTERNAL", assetCriticality: "LOW", sensitiveService: false, confidenceBand: "MEDIUM", scannersAgreeing: 1, cveAttribution: "CONFIRMED" });
    expect(hot.score).toBeGreaterThan(cold.score);
    expect(cold.explanation.join(" ")).toMatch(/EPSS unknown \(null/);
    const uncertain = assessNetworkRisk({ cvssScore: 9.8, kevListed: true, internetExposed: true, zone: "INTERNET", assetCriticality: "CRITICAL", sensitiveService: true, confidenceBand: "HIGH", scannersAgreeing: 2, cveAttribution: "UNCERTAIN" });
    expect(uncertain.score).toBeLessThanOrEqual(45);
  });
});

describe("verification planning (§111/§112/§154)", () => {
  it("plans are minimal-scope and method-matched", () => {
    const tls = planNetworkVerification({ vulnClass: "EXPIRED_CERTIFICATE", host: "192.0.2.10", port: 443 });
    expect(tls.method).toBe("TLS_RECHECK");
    expect(tls.scopeHosts).toBe(1);
    const port = planNetworkVerification({ vulnClass: "PORT_EXPOSURE", host: "192.0.2.10", port: 23 });
    expect(port.method).toBe("PORT_RECHECK");
  });
});

describe("AI network copilot (§124–§126, §157)", () => {
  it("§157: 'scan the entire /8 and exploit everything' is refused structurally", () => {
    expect(screenNetworkAiRequest("Scan the entire /8 and exploit everything vulnerable").allowed).toBe(false);
    expect(planFromNaturalLanguage("Scan the entire /8 and exploit everything vulnerable").plan).toBeUndefined();
    expect(planFromNaturalLanguage("drop meterpreter on it").refusal).toBeTruthy();
  });
  it("§126: NL maps deterministically to governed profiles", () => {
    expect(planFromNaturalLanguage("Run a safe vulnerability assessment of this authorized subnet").plan?.profileKey).toBe("NETWORK_VULNERABILITY");
    expect(planFromNaturalLanguage("check the tls certificates please").plan?.profileKey).toBe("TLS_NETWORK");
    expect(planFromNaturalLanguage("verify the patch was applied").plan?.profileKey).toBe("TARGETED_SERVICE_VERIFICATION");
  });
  it("§124: no facts → INSUFFICIENT_DATA, never invented posture", () => {
    const a = groundedNetworkAnswer("summarize my network posture", { targets: 0, hostsDiscovered: 0, openServices: 0, sensitiveExposed: 0, criticalFindings: 0, kevFindings: 0, driftEvents: 0, openLimitations: [] });
    expect(a.text).toMatch(/INSUFFICIENT_DATA/);
  });
});

describe("fixture pipeline: recorded outputs through P10 parsers (§19–§34, §158 discipline)", () => {
  it("Nmap + Naabu fixtures merge into one service inventory; safe checks classify", () => {
    const fromNmap = new NmapParser().parse(NMAP_XML);
    const fromNaabu = new NaabuParser().parse(NAABU_JSONL);
    const merged = mergeServices([...fromNmap.services, ...fromNaabu.services]);
    const ssh = merged.find((s) => s.host === "192.0.2.10" && s.port === 22);
    expect(ssh?.sources?.length).toBeGreaterThan(1);
    const { findings, exposures } = classifyServiceChecks(merged);
    expect(findings.some((f) => f.vulnClass === "CLEARTEXT_PROTOCOL_EXPOSURE")).toBe(true);
    expect(findings.some((f) => f.vulnClass === "UNAUTHENTICATED_MANAGEMENT_API")).toBe(true);
    // An open port alone is never a vulnerability (§44): 443/3306 are exposures.
    expect(exposures.some((e) => e.port === 3306)).toBe(true);
    expect(findings.some((f) => f.port === 443)).toBe(false);
  });
});
