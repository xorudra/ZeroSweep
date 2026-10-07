import { describe, expect, it } from "vitest";
import {
  LocalEchoAdapter, MockSecurityAdapter, ToolRegistry,
  createNetworkAdapters, networkFixtureResponses, networkHealthBySlug, FixtureToolRunner,
} from "@dsrclone/security-sdk";
import type { ScopeRules } from "@dsrclone/validation";
import { DagRunner } from "./consumers/dag-runner";
import { EXECUTABLE_SLUGS, StageExecutor } from "./executors/stage-executor";
import { FakeStore } from "./testing/fake-store";

/**
 * Prompt 10 E2E (fixtures only — §76–§83): the NETWORK_BASELINE pipeline
 * runs host discovery → port discovery → service detection → safe
 * checks over a documentation-range CIDR target (192.0.2.0/24, RFC 5737)
 * with recorded tool output. No binary runs and no network is touched:
 * FixtureToolRunner supplies every byte.
 */

const NETWORK_SCOPE: ScopeRules = {
  includeHosts: [], excludeHosts: [], includeCidrs: ["192.0.2.0/24"],
  allowedPorts: [], allowedPaths: [], excludedPaths: [],
};

type NetworkProfile = "NETWORK_DISCOVERY" | "NETWORK_BASELINE" | "NETWORK_INTERNAL";

function makeWorld(profile: NetworkProfile, opts: { masscanApproved?: boolean; workerCapabilities?: string[] } = {}) {
  const fixtures = networkFixtureResponses();
  const planRegistry = new ToolRegistry();
  planRegistry.register(new MockSecurityAdapter());
  planRegistry.register(new LocalEchoAdapter());
  const planAdapters = createNetworkAdapters(new FixtureToolRunner(fixtures));
  for (const a of planAdapters) planRegistry.register(a);
  const store = new FakeStore(profile, {
    planRegistry,
    healthBySlug: networkHealthBySlug(planAdapters),
    executableSlugs: [...EXECUTABLE_SLUGS],
    targetType: "CIDR",
    networkTarget: {
      targetValue: "192.0.2.0/24", targetHost: "192.0.2.0", scope: NETWORK_SCOPE,
      ...(opts.masscanApproved !== undefined ? { masscanApproved: opts.masscanApproved } : {}),
    },
  });
  const execRegistry = new ToolRegistry();
  execRegistry.register(new MockSecurityAdapter());
  execRegistry.register(new LocalEchoAdapter());
  for (const a of createNetworkAdapters(new FixtureToolRunner(fixtures))) execRegistry.register(a);
  const executor = new StageExecutor(execRegistry, store, undefined, { workerCapabilities: opts.workerCapabilities ?? [] });
  return { store, dag: new DagRunner(store, executor), executor };
}

describe("Prompt 10 E2E — NETWORK_BASELINE over a fixture CIDR", () => {
  it("runs the full network DAG, merges multi-scanner services, correlates governed findings", async () => {
    const { store, dag } = makeWorld("NETWORK_BASELINE");
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    for (const stage of ["TARGET_EXPANSION", "HOST_DISCOVERY", "PORT_DISCOVERY", "SERVICE_DETECTION", "SAFE_NETWORK_CHECKS", "CORRELATION", "RISK_ANALYSIS"]) {
      expect(store.stages.get(stage), stage).toBe("COMPLETED");
    }

    // Target expansion (§5/§62): bounded chunks persisted, counts emitted.
    expect(store.networkChunks).toHaveLength(1);
    expect(store.networkChunks[0]).toMatchObject({ rangeStart: "192.0.2.1", rangeEnd: "192.0.2.254", hostCount: 254 });
    expect(store.events.some((e) => e.type === "network.targets_expanded")).toBe(true);

    // Only the right adapters ran — Masscan is capability-isolated from
    // every default stage, local discovery needs an internal profile.
    const executed = [...store.executions.values()].map((e) => e.adapterSlug);
    expect(executed).toEqual(expect.arrayContaining(["nmap", "naabu", "rustscan"]));
    expect(executed).not.toContain("masscan");
    expect(executed).not.toContain("netdiscover");
    expect(executed).not.toContain("arp-scan");

    // Assets: the two live hosts are IN_SCOPE; the hostname alias is a
    // recorded relationship but OUT_OF_SCOPE under a CIDR-only scope —
    // it never becomes a scan target (§51 + scope discipline).
    const inScope = store.assets.filter((a) => a.scopeStatus === "IN_SCOPE").map((a) => a.host).sort();
    expect(inScope).toEqual(["192.0.2.10", "192.0.2.11"]);
    expect(store.assets.find((a) => a.host === "server.example.com")?.scopeStatus).toBe("OUT_OF_SCOPE");
    const hostAsset = store.assets.find((a) => a.host === "192.0.2.10")!;
    expect(hostAsset.osHint).toBe("Linux 5.15");

    // Port merge (§49/§80): ONE canonical row for 192.0.2.10:80 with all
    // three scanners' provenance and Nmap's rich fingerprint; the
    // naabu-only port survives; closed stays closed.
    const port80 = store.services.filter((s) => s.host === "192.0.2.10" && s.port === 80);
    expect(port80).toHaveLength(1);
    expect(port80[0]!.sources!.sort()).toEqual(["naabu", "nmap", "rustscan"]);
    expect(port80[0]!.product).toBe("Apache httpd");
    expect(port80[0]!.cpe).toBe("cpe:/a:apache:http_server:2.4.49");
    expect(store.services.some((s) => s.port === 9999)).toBe(true);
    expect(store.services.find((s) => s.port === 8080)!.state).toBe("CLOSED");
    expect(store.services.find((s) => s.port === 443)!.tls).toBe(true);

    // Findings: exactly the three governed classes, correlated to one
    // canonical finding each (§52/§53) — open ports alone made none.
    const canonical = store.correlatedFindings.filter((f) => f.vulnClass);
    expect(canonical.map((f) => f.vulnClass).sort()).toEqual([
      "CLEARTEXT_PROTOCOL_EXPOSURE", "SMB_SIGNING_NOT_REQUIRED", "UNAUTHENTICATED_MANAGEMENT_API",
    ]);
    for (const f of canonical) expect(f.riskScore).toBeGreaterThan(0);
    expect(store.findingStats?.duplicatesMerged).toBeGreaterThan(0);

    // NSE governance is frozen into the SAFE_CHECKS execution record:
    // SAFE scripts selected, intrusive ones never selected (§14).
    const checksExec = [...store.executions.values()].find((e) => e.stageType === "SAFE_NETWORK_CHECKS")!;
    const metrics = checksExec.patch.metrics as { nseScriptsSelected?: string[]; nseSnapshot?: { version?: string } };
    expect(metrics.nseSnapshot?.version).toBeTruthy();
    expect(metrics.nseScriptsSelected).toContain("banner");
    expect(metrics.nseScriptsSelected).not.toContain("smb-vuln-ms17-010");
    expect(metrics.nseScriptsSelected).not.toContain("ssh-brute");

    // Aggregated network events (§84).
    for (const type of ["network.host_discovered", "network.port_discovered", "network.service_identified"] as const) {
      expect(store.events.some((e) => e.type === type), type).toBe(true);
    }
    expect(store.reportPending).toBe(true);
  });

  it("NETWORK_DISCOVERY has no SAFE_NETWORK_CHECKS stage and still completes", async () => {
    const { store, dag } = makeWorld("NETWORK_DISCOVERY");
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    expect(store.plan.stages.map((s) => s.type)).not.toContain("SAFE_NETWORK_CHECKS");
    expect(store.assets.filter((a) => a.scopeStatus === "IN_SCOPE")).toHaveLength(2);
  });
});

describe("Prompt 10 policy gates (§81)", () => {
  it("NETWORK_INTERNAL local discovery is UNAVAILABLE_FOR_WORKER on a general worker, works on an internal one", async () => {
    const general = makeWorld("NETWORK_INTERNAL");
    const r1 = await general.dag.run("scan-1");
    // Nmap still delivers, so the scan completes with PARTIAL data —
    // the local-discovery capability is degraded, never faked (§55/§56).
    expect(r1.status).toBe("PARTIAL");
    expect(general.store.stages.get("HOST_DISCOVERY")).toBe("PARTIAL");
    const ndExec = [...general.store.executions.values()].find((e) => e.adapterSlug === "netdiscover")!;
    expect(String(ndExec.patch.error ?? "")).toContain("UNAVAILABLE_FOR_WORKER");
    expect(general.store.events.some((e) => e.type === "network.local_discovery_unavailable")).toBe(true);
    expect(general.store.assets.some((a) => a.host === "192.0.2.1")).toBe(false);

    const internal = makeWorld("NETWORK_INTERNAL", { workerCapabilities: ["LOCAL_LAYER2_ACCESS"] });
    const r2 = await internal.dag.run("scan-1");
    expect(r2.status).toBe("COMPLETED");
    expect(internal.store.assets.some((a) => a.host === "192.0.2.1")).toBe(true); // ARP-discovered router
  });

  it("Masscan is denied without a recorded approval and runs only with one (§19/§20)", async () => {
    const denied = makeWorld("NETWORK_BASELINE");
    const exec = await denied.store.ensureExecution("scan-1", "PORT_DISCOVERY", "masscan", 1);
    const outcome = await denied.executor.run({ kind: "STAGE_EXECUTION", scanId: "scan-1", stageId: "PORT_DISCOVERY", toolExecutionId: exec.id, attempt: 1 });
    expect(outcome).toMatchObject({ status: "DENIED", reasonCode: "MASSCAN_NOT_APPROVED" });
    expect(denied.store.events.some((e) => e.type === "network.masscan_denied")).toBe(true);

    const approved = makeWorld("NETWORK_BASELINE", { masscanApproved: true });
    const exec2 = await approved.store.ensureExecution("scan-1", "PORT_DISCOVERY", "masscan", 1);
    const outcome2 = await approved.executor.run({ kind: "STAGE_EXECUTION", scanId: "scan-1", stageId: "PORT_DISCOVERY", toolExecutionId: exec2.id, attempt: 1 });
    expect(outcome2.status).toBe("COMPLETED");
    expect(approved.store.services.some((s) => s.port === 80 && (s.sources ?? []).includes("masscan"))).toBe(true);
  });
});
