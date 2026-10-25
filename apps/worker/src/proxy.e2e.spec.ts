import { describe, expect, it } from "vitest";
import {
  FixtureToolRunner, LocalEchoAdapter, MockSecurityAdapter, ToolRegistry,
  NUCLEI_JSONL, NIKTO_JSON, SSLYZE_JSON, TESTSSL_JSON,
  createVulnAdapters, vulnHealthBySlug,
  createProxyAdapters, proxyHealthBySlug,
  InMemoryScannerInstanceProvider, InMemorySessionProfileProvider, MapEndpointResolver, MapSecretResolver,
  FIXTURE_INSTANCES, FIXTURE_ENDPOINTS, FIXTURE_SECRETS, createFixtureTransport,
  type ConnectorDeps, type ScannerInstanceRecord, type SessionProfileRecord,
} from "@zerosweep/security-sdk";
import { StageExecutor, EXECUTABLE_SLUGS } from "./executors/stage-executor";
import { DagRunner } from "./consumers/dag-runner";
import { FakeStore } from "./testing/fake-store";

/**
 * Prompt 8 end-to-end scenarios (§64–§69): the ZAP/Burp/Caido connectors
 * run the full pipeline (plan → gated execution → passive pipeline →
 * normalize → persist → CORRELATION) against RECORDED FIXTURE transports.
 * No scanner exists, no network is touched, no live target exists. The
 * cross-tool scenario proves a missing-CSP issue reported by Nuclei, ZAP,
 * Burp and Caido becomes ONE canonical finding with four sources (§33).
 */

const SESSION_PROFILE: SessionProfileRecord = {
  id: "sp-1", workspaceId: "ws-1", name: "Fixture authenticated session",
  type: "AUTHENTICATED", credentialReference: "APP_SESSION_FIXTURE",
  validation: { authenticatedUrl: "https://example.com/account", expectedStatus: 200 },
  createdBy: "u-1", createdAt: "2026-10-07T00:00:00Z", updatedAt: "2026-10-07T00:00:00Z",
};

function proxyDeps(instances: ScannerInstanceRecord[]): ConnectorDeps {
  return {
    instances: new InMemoryScannerInstanceProvider(instances),
    endpoints: new MapEndpointResolver(FIXTURE_ENDPOINTS),
    secrets: new MapSecretResolver(FIXTURE_SECRETS),
    sessions: new InMemorySessionProfileProvider([SESSION_PROFILE]),
    transport: createFixtureTransport(),
  };
}

const VULN_FIXTURES = {
  nuclei: { stdout: NUCLEI_JSONL, version: "3.3.0" },
  nikto: { stdout: NIKTO_JSON, version: "2.5.0" },
  "testssl.sh": { stdout: TESTSSL_JSON, version: "3.2" },
  sslyze: { stdout: SSLYZE_JSON, version: "6.0.0" },
};

function makeWorld(instances: ScannerInstanceRecord[]) {
  const buildRegistry = () => {
    const r = new ToolRegistry();
    r.register(new MockSecurityAdapter());
    r.register(new LocalEchoAdapter());
    for (const a of createVulnAdapters(new FixtureToolRunner(VULN_FIXTURES))) r.register(a);
    for (const a of createProxyAdapters(proxyDeps(instances))) r.register(a);
    return r;
  };
  const planRegistry = buildRegistry();
  const healthBySlug = {
    ...vulnHealthBySlug(createVulnAdapters(new FixtureToolRunner(VULN_FIXTURES))),
    ...proxyHealthBySlug(instances),
  };
  const scannerBySlug: Record<string, { instanceId: string; sessionProfileId?: string }> = {};
  for (const inst of instances) {
    scannerBySlug[inst.toolSlug] = { instanceId: inst.id, ...(inst.toolSlug === "owasp-zap" ? { sessionProfileId: "sp-1" } : {}) };
  }
  const store = new FakeStore("WEB_COMPREHENSIVE", {
    planRegistry, healthBySlug, scannerBySlug,
    executableSlugs: [...EXECUTABLE_SLUGS],
    targetType: "WEB_APPLICATION",
  });
  const executor = new StageExecutor(buildRegistry(), store);
  return { store, dag: new DagRunner(store, executor) };
}

describe("Prompt 8 E2E — all three connectors configured", () => {
  it("runs the passive stage, merges CSP across Nuclei+ZAP+Burp+Caido, persists redacted traffic", async () => {
    const { store, dag } = makeWorld(FIXTURE_INSTANCES);
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    expect(store.stages.get("PASSIVE_SECURITY_ANALYSIS")).toBe("COMPLETED");

    const executed = [...store.executions.values()].map((e) => e.adapterSlug);
    expect(executed).toEqual(expect.arrayContaining(["owasp-zap", "burp-suite-professional", "caido"]));

    // §33/§36: ONE canonical missing-CSP finding, four sources, all
    // evidence rows preserved.
    const csp = store.correlatedFindings.find((f) => f.vulnClass === "MISSING_SECURITY_HEADERS" && (f.endpoint ?? "").endsWith("example.com/"));
    expect(csp).toBeDefined();
    expect([...csp!.sources].sort()).toEqual(expect.arrayContaining(["nuclei", "owasp-zap", "burp-suite-professional", "caido"]));
    expect(csp!.evidenceRows.length).toBeGreaterThanOrEqual(4);

    // Burp's unique reflected-XSS issue stays its own canonical finding.
    const xss = store.correlatedFindings.find((f) => f.vulnClass === "XSS");
    expect(xss).toBeDefined();
    expect(xss!.sources).toEqual(["burp-suite-professional"]);
    expect(xss!.verificationStatus).not.toBe("CONFIRMED");

    // Traffic persisted with scope verdicts; the out-of-scope ZAP URL is
    // recorded as an OUT_OF_SCOPE endpoint, never promoted (§30).
    expect(store.transactions.length).toBeGreaterThanOrEqual(4);
    expect(store.transactions.every((t) => t.requestHash)).toBe(true);
    const oos = store.endpoints.find((e) => e.url.includes("thirdparty.example.net"));
    expect(oos?.scopeStatus).toBe("OUT_OF_SCOPE");
    expect(store.webSockets.some((w) => w.url === "wss://example.com/socket")).toBe(true);

    // §20/§27: no fixture secret survives anywhere in persisted state.
    const persisted = JSON.stringify({ findings: store.findings, transactions: store.transactions, correlated: store.correlatedFindings });
    for (const secret of ["fixture-zap-secret", "fixture-zap-token", "fixture-burp-secret", "fixture-burp-token", "fixture-caido-secret", "fixture-caido-token", "fixture-zap-api-key"]) {
      expect(persisted).not.toContain(secret);
    }

    // §72 lifecycle events + §23 session expiry (the /account probe in the
    // ZAP fixture redirects to the login page).
    const types = store.events.map((e) => e.type);
    expect(types).toContain("passive_analysis.started");
    expect(types).toContain("passive_analysis.completed");
    expect(types).toContain("scanner.context_created");
    expect(types).toContain("scanner.context_destroyed");
    expect(types).toContain("auth_session.expired");

    // Imported ZAP endpoints join the same inventory (§30/§31).
    expect(store.endpoints.some((e) => e.url === "https://example.com/login" && e.sources.includes("owasp-zap"))).toBe(true);
  });
});

describe("Prompt 8 E2E — no scanner configured (§66)", () => {
  it("skips the passive stage honestly: no executions, no fake findings, scan still completes", async () => {
    const { store, dag } = makeWorld([]);
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    expect(store.stages.get("PASSIVE_SECURITY_ANALYSIS")).toBe("COMPLETED");
    const executed = [...store.executions.values()].map((e) => e.adapterSlug);
    expect(executed).not.toContain("owasp-zap");
    expect(executed).not.toContain("burp-suite-professional");
    expect(executed).not.toContain("caido");
    expect(store.events.some((e) => e.type === "passive_analysis.skipped")).toBe(true);
    expect(store.transactions).toHaveLength(0);
    // Findings come only from the real vuln adapters — nothing invented.
    expect(store.findings.every((f) => f.sourceTool !== "owasp-zap" && f.sourceTool !== "burp-suite-professional" && f.sourceTool !== "caido")).toBe(true);
  });
});

describe("Prompt 8 E2E — Burp NOT_CONFIGURED, ZAP + Caido configured (§66)", () => {
  it("runs the configured connectors only; Burp contributes nothing and is never simulated", async () => {
    const instances = FIXTURE_INSTANCES.filter((i) => i.toolSlug !== "burp-suite-professional");
    const { store, dag } = makeWorld(instances);
    const result = await dag.run("scan-1");
    expect(result.status).toBe("COMPLETED");
    expect(store.stages.get("PASSIVE_SECURITY_ANALYSIS")).toBe("COMPLETED");
    const executed = [...store.executions.values()].map((e) => e.adapterSlug);
    expect(executed).toEqual(expect.arrayContaining(["owasp-zap", "caido"]));
    expect(executed).not.toContain("burp-suite-professional");
    const csp = store.correlatedFindings.find((f) => f.vulnClass === "MISSING_SECURITY_HEADERS" && (f.endpoint ?? "").endsWith("example.com/"));
    expect(csp).toBeDefined();
    expect(csp!.sources).toContain("owasp-zap");
    expect(csp!.sources).toContain("caido");
    expect(csp!.sources).not.toContain("burp-suite-professional");
    // No Burp-only XSS finding exists in this world.
    expect(store.correlatedFindings.some((f) => f.vulnClass === "XSS")).toBe(false);
  });
});
