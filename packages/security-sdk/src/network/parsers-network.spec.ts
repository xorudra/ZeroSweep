import { describe, expect, it } from "vitest";
import {
  ArpScanParser, MasscanParser, NaabuParser, NetdiscoverParser, NmapParser, RustScanParser, TsharkParser,
} from "./parsers-network";
import * as F from "./fixtures-network";
import { mergeServices } from "./aggregator";
import { classifyServiceChecks, classifyScriptOutput } from "./network-checks";
import { parseXmlLite } from "./xml-lite";

describe("hardened XML reader (§16/§75)", () => {
  it("rejects DOCTYPE with internal subset / ENTITY / external reference (XXE)", () => {
    const r = parseXmlLite(F.NMAP_DOCTYPE_ATTACK);
    expect("error" in r).toBe(true);
    const ext = parseXmlLite(`<!DOCTYPE nmaprun SYSTEM "https://nmap.org/book/nmap.dtd"><nmaprun/>`);
    expect("error" in ext).toBe(true);
  });
  it("tolerates the bare DOCTYPE real Nmap emits, rejects malformed input", () => {
    expect("root" in parseXmlLite(F.NMAP_XML)).toBe(true);
    expect("error" in parseXmlLite("<nmaprun><host></nmaprun>")).toBe(true);
    expect("error" in parseXmlLite("not xml at all")).toBe(true);
  });
});

describe("NmapParser: inventory, services, governed findings (§15/§29–§37)", () => {
  const parsed = new NmapParser().parse(F.NMAP_XML);

  it("live hosts become assets with OS hints; down hosts contribute nothing", () => {
    const hosts = parsed.assets.map((a) => a.host);
    expect(hosts).toContain("192.0.2.10");
    expect(hosts).toContain("192.0.2.11");
    expect(hosts).toContain("server.example.com");
    expect(hosts).not.toContain("192.0.2.12");
    const hostAsset = parsed.assets.find((a) => a.host === "192.0.2.10")!;
    expect(hostAsset.osHint).toBe("Linux 5.15");
    expect(hostAsset.osConfidence).toBe(0.96);
  });

  it("services carry state, product/version, CPE and TLS facts (§29–§34)", () => {
    const tls = parsed.services.find((s) => s.port === 443)!;
    expect(tls.tls).toBe(true);
    expect(tls.product).toBe("nginx");
    expect(tls.cpe).toBe("cpe:/a:nginx:nginx:1.25.3");
    const closed = parsed.services.find((s) => s.port === 8080)!;
    expect(closed.state).toBe("CLOSED");
    const ssh = parsed.services.find((s) => s.port === 22)!;
    expect(ssh.confidence).toBe(1); // nmap conf=10 probed
  });

  it("findings come ONLY from governed checks: telnet, docker API, SMB signing", () => {
    const classes = parsed.findings.map((f) => f.vulnClass).sort();
    expect(classes).toEqual(["CLEARTEXT_PROTOCOL_EXPOSURE", "SMB_SIGNING_NOT_REQUIRED", "UNAUTHENTICATED_MANAGEMENT_API"]);
    for (const f of parsed.findings) {
      expect(f.sourceFingerprint).toMatch(/^[0-9a-f]{64}$/);
      expect(f.sourceTool).toBe("nmap");
    }
    // The open SSH/MySQL/RDP ports produced NO findings (§32/§39/§40).
    expect(parsed.findings.some((f) => f.port === 22 || f.port === 3306 || f.port === 3389)).toBe(false);
  });

  it("database and remote-admin services are exposure observations, not findings", () => {
    const kinds = parsed.exposures.map((e) => `${e.kind}:${e.port}`).sort();
    expect(kinds).toContain("DATABASE_SERVICE:3306");
    expect(kinds).toContain("REMOTE_ADMIN_SERVICE:22");
    expect(kinds).toContain("REMOTE_ADMIN_SERVICE:3389");
    expect(parsed.observations.some((o) => o.summary.includes("http-title"))).toBe(true);
  });
});

describe("safe-check policy edge cases (§37–§42)", () => {
  it("an open port alone is NEVER a finding", () => {
    const { findings, exposures } = classifyServiceChecks([
      { host: "192.0.2.20", port: 22, protocol: "tcp", name: "ssh", state: "OPEN" },
      { host: "192.0.2.20", port: 5432, protocol: "tcp", name: "postgresql", state: "OPEN" },
    ]);
    expect(findings).toHaveLength(0);
    expect(exposures).toHaveLength(2);
  });
  it("TLS-wrapped variants do not trigger cleartext findings", () => {
    const { findings } = classifyServiceChecks([
      { host: "192.0.2.20", port: 990, protocol: "tcp", name: "ftps", tls: true, state: "OPEN" },
      { host: "192.0.2.20", port: 2376, protocol: "tcp", name: "docker", tls: true, state: "OPEN" },
    ]);
    expect(findings).toHaveLength(0);
  });
  it("script output confirms a finding ONLY via a governed declaration + pattern", () => {
    expect(classifyScriptOutput({ host: "192.0.2.10", port: 445, scriptId: "smb2-security-mode", output: "Message signing enabled but not required" })).toBeNull(); // no declaration
    const hit = classifyScriptOutput({ host: "192.0.2.10", port: 445, scriptId: "smb2-security-mode", output: "Message signing enabled but not required", declaredVulnClass: "SMB_SIGNING_NOT_REQUIRED" });
    expect(hit?.vulnClass).toBe("SMB_SIGNING_NOT_REQUIRED");
    expect(classifyScriptOutput({ host: "192.0.2.10", port: 445, scriptId: "smb2-security-mode", output: "Message signing is required", declaredVulnClass: "SMB_SIGNING_NOT_REQUIRED" })).toBeNull();
  });
});

describe("fast discovery parsers (§17–§20)", () => {
  it("naabu: ports are low-confidence inventory; checks still apply", () => {
    const parsed = new NaabuParser().parse(F.NAABU_JSONL);
    expect(parsed.services).toHaveLength(9);
    expect(parsed.services.find((s) => s.port === 443)!.tls).toBe(true);
    expect(parsed.services.every((s) => s.confidence === 0.5)).toBe(true);
    // Naabu reports no service NAMES, so its telnet port cannot be
    // confirmed cleartext by naabu alone (§37) — only the by-design
    // unauthenticated Docker API port fires. Nmap's service stage is
    // what confirms the telnet finding in the pipeline.
    expect(parsed.findings.map((f) => f.vulnClass)).toEqual(["UNAUTHENTICATED_MANAGEMENT_API"]);
  });
  it("rustscan: greppable + Open lines merge, junk lines warn", () => {
    const parsed = new RustScanParser().parse(F.RUSTSCAN_TEXT);
    expect(parsed.services.map((s) => `${s.host}:${s.port}`).sort()).toEqual(["192.0.2.10:22", "192.0.2.10:443", "192.0.2.10:80", "192.0.2.11:3389"]);
    expect(parsed.findings).toHaveLength(0);
  });
  it("masscan: JSON list; hostile banner is sanitized before storage", () => {
    const parsed = new MasscanParser().parse(F.MASSCAN_JSON);
    const http = parsed.services.find((s) => s.port === 80)!;
    expect(http.banner).not.toContain("<script>");
    expect(http.banner).not.toContain("\u001b");
    expect(parsed.findings.map((f) => f.vulnClass)).toEqual(["UNAUTHENTICATED_MANAGEMENT_API"]);
    const bad = new MasscanParser().parse("{broken");
    expect(bad.services).toHaveLength(0);
    expect(bad.warnings.length).toBeGreaterThan(0);
  });
});

describe("local discovery parsers (§21/§22)", () => {
  it("netdiscover + arp-scan produce assets only, never services/findings", () => {
    const nd = new NetdiscoverParser().parse(F.NETDISCOVER_TEXT);
    expect(nd.assets.map((a) => a.host)).toEqual(["192.0.2.1", "192.0.2.10"]);
    const arp = new ArpScanParser().parse(F.ARP_SCAN_XML);
    expect(arp.assets).toHaveLength(2);
    expect(arp.services).toHaveLength(0);
    expect(arp.findings).toHaveLength(0);
  });
});

describe("tshark offline analysis (§45)", () => {
  it("extracts protocol metrics and HTTP transactions from capture JSON", () => {
    const parsed = new TsharkParser().parse(F.TSHARK_JSON);
    expect(parsed.records).toBe(3);
    expect(parsed.transactions).toHaveLength(2);
    expect(parsed.transactions[0]).toMatchObject({ method: "GET", host: "server.example.com", path: "/login" });
    expect(parsed.transactions[1]).toMatchObject({ statusCode: 200 });
    expect(parsed.metrics.proto_dns).toBe(1);
  });
});

describe("PortResultAggregator (§49)", () => {
  it("merges four scanners into one canonical service, provenance preserved", () => {
    const nmap = new NmapParser().parse(F.NMAP_XML);
    const naabu = new NaabuParser().parse(F.NAABU_JSONL);
    const rust = new RustScanParser().parse(F.RUSTSCAN_TEXT);
    const mass = new MasscanParser().parse(F.MASSCAN_JSON);
    const merged = mergeServices([...nmap.services, ...naabu.services, ...rust.services, ...mass.services]);
    const port80 = merged.filter((s) => s.host === "192.0.2.10" && s.port === 80);
    expect(port80).toHaveLength(1);
    expect(port80[0]!.sources!.sort()).toEqual(["masscan", "naabu", "nmap", "rustscan"]);
    expect(port80[0]!.product).toBe("Apache httpd"); // richest evidence wins
    // naabu-only port survives; closed stays closed unless someone saw it open
    expect(merged.some((s) => s.port === 9999 && s.host === "192.0.2.10")).toBe(true);
    const closed = merged.find((s) => s.port === 8080)!;
    expect(closed.state).toBe("CLOSED");
    const opened = mergeServices([
      { host: "192.0.2.30", port: 8080, protocol: "tcp", state: "CLOSED", sources: ["nmap"] },
      { host: "192.0.2.30", port: 8080, protocol: "tcp", state: "OPEN", sources: ["masscan"] },
    ]);
    expect(opened[0]!.state).toBe("OPEN");
    expect(opened[0]!.sources!.sort()).toEqual(["masscan", "nmap"]);
  });
});
