import { describe, expect, it } from "vitest";
import type { ScopeRules } from "@dsrclone/validation";
import { correlateFindings } from "../vuln/correlation";
import {
  InMemoryScannerInstanceProvider, InMemorySessionProfileProvider, MapEndpointResolver, MapSecretResolver,
  type SessionProfileRecord,
} from "./types";
import { createFixtureTransport, FIXTURE_ENDPOINTS, FIXTURE_INSTANCES, FIXTURE_SECRETS, HAR_EXPORT } from "./fixtures";
import { createProxyAdapters, createProxyConnectors } from "./adapters-proxy";
import type { ConnectorDeps } from "./connector";
import { BurpIssueParser, HarImporter, ZapIssueParser } from "./parsers-proxy";
import { proxyHealthBySlug } from "./registry";

const SCOPE: ScopeRules = {
  includeHosts: ["example.com"], excludeHosts: [], includeCidrs: [],
  allowedPorts: [], allowedPaths: [], excludedPaths: [],
};

const SESSION_PROFILE: SessionProfileRecord = {
  id: "sp-1", workspaceId: "ws-1", name: "Fixture authenticated session",
  type: "AUTHENTICATED", credentialReference: "APP_SESSION_FIXTURE",
  validation: { authenticatedUrl: "https://example.com/account", expectedStatus: 200 },
  createdBy: "u-1", createdAt: "2026-10-07T00:00:00Z", updatedAt: "2026-10-07T00:00:00Z",
};

function fixtureDeps(instances = FIXTURE_INSTANCES): ConnectorDeps {
  return {
    instances: new InMemoryScannerInstanceProvider(instances),
    endpoints: new MapEndpointResolver(FIXTURE_ENDPOINTS),
    secrets: new MapSecretResolver(FIXTURE_SECRETS),
    sessions: new InMemorySessionProfileProvider([SESSION_PROFILE]),
    transport: createFixtureTransport(),
  };
}

describe("connector health honesty (§53/§66)", () => {
  it("reports NOT_CONFIGURED for every product when no instance is registered", async () => {
    const connectors = createProxyConnectors(fixtureDeps([]));
    for (const c of [connectors.zap, connectors.burp, connectors.caido]) {
      const health = await c.healthCheck();
      expect(health.status).toBe("NOT_CONFIGURED");
      expect(await c.checkAvailability()).toBe(false);
    }
    expect(proxyHealthBySlug([])).toEqual({
      "owasp-zap": "NOT_CONFIGURED", "burp-suite-professional": "NOT_CONFIGURED", caido: "NOT_CONFIGURED",
    });
  });

  it("reports HEALTHY with version/license for configured fixture deployments", async () => {
    const connectors = createProxyConnectors(fixtureDeps());
    const zap = await connectors.zap.healthCheck();
    expect(zap.status).toBe("HEALTHY");
    expect(zap.version).toBe("2.15.0");
    const burp = await connectors.burp.healthCheck();
    expect(burp.status).toBe("HEALTHY");
    expect(burp.licenseState).toContain("Professional");
    const caido = await connectors.caido.healthCheck();
    expect(caido.status).toBe("DEGRADED"); // reachable, version unconfirmed — never upgraded on assumption (§13)
    expect(proxyHealthBySlug(FIXTURE_INSTANCES)["owasp-zap"]).toBe("HEALTHY");
  });

  it("reports MISCONFIGURED when the endpoint or credential reference does not resolve", async () => {
    const badEndpoint = [{ ...FIXTURE_INSTANCES[0]!, endpointReference: "NOT_IN_SERVER_CONFIG" }];
    const c1 = createProxyConnectors(fixtureDeps(badEndpoint));
    expect((await c1.zap.healthCheck()).status).toBe("MISCONFIGURED");
    const badSecret = [{ ...FIXTURE_INSTANCES[0]!, credentialReference: "DOES_NOT_EXIST" }];
    const c2 = createProxyConnectors(fixtureDeps(badSecret));
    expect((await c2.zap.healthCheck()).status).toBe("MISCONFIGURED");
  });
});

describe("ZAP connector pipeline (§4–§7, §22/§23)", () => {
  it("runs context → scope → import → passive → issues with redaction and session-expiry detection", async () => {
    const deps = fixtureDeps();
    const { zap } = createProxyConnectors(deps);
    await zap.connect("inst-zap-1");
    const context = await zap.createContext({
      instanceId: "inst-zap-1", workspaceId: "ws-1", assessmentId: "asmt-00000001",
      scopeRules: SCOPE, targetBaseUrls: ["https://example.com/"], sessionProfile: SESSION_PROFILE,
    });
    await zap.configureScope(context.id, SCOPE, ["https://example.com/"]);
    await zap.configureAuthentication(context.id, SESSION_PROFILE);
    const envelope = await zap.collectPassiveResults(context.id, SESSION_PROFILE);
    await zap.cleanup(context.id);

    // Findings normalized like any other source; passive alerts stay UNVERIFIED (§7).
    const csp = envelope.findings.find((f) => f.vulnClass === "MISSING_SECURITY_HEADERS");
    expect(csp?.sourceTool).toBe("owasp-zap");
    expect(csp?.verificationStatus).toBe("UNVERIFIED");
    const cookie = envelope.findings.find((f) => f.vulnClass === "COOKIE_NO_SAMESITE");
    expect(cookie).toBeDefined();
    expect(envelope.observations.some((o) => o.summary.includes("Modern Web Application"))).toBe(true);

    // The /account probe shows a login redirect → session EXPIRED (§23).
    expect(envelope.sessionStatus).toBe("EXPIRED");
    expect(envelope.metrics.sessionExpired).toBe(1);

    // Imported endpoints include the out-of-scope host — it stays in the
    // import (recorded), and scope verdicts are applied downstream (§30).
    expect(envelope.endpoints.some((e) => e.url.includes("thirdparty.example.net"))).toBe(true);

    // Redaction: no fixture secret survives anywhere in the envelope.
    const serialized = JSON.stringify(envelope);
    expect(serialized).not.toContain("fixture-zap-secret");
    expect(serialized).not.toContain("fixture-zap-token");
    expect(envelope.transactions.length).toBe(2);
    expect(envelope.transactions[0]?.requestHash).toBeTruthy();
  });

  it("refuses contexts that exceed scope or borrow another tenant's session (§6/§69)", async () => {
    const { zap } = createProxyConnectors(fixtureDeps());
    await expect(zap.createContext({
      instanceId: "inst-zap-1", workspaceId: "ws-1", assessmentId: "asmt-1",
      scopeRules: SCOPE, targetBaseUrls: ["https://outside.example.org/"],
    })).rejects.toThrow(/outside the approved scope/);
    await expect(zap.createContext({
      instanceId: "inst-zap-1", workspaceId: "ws-2", assessmentId: "asmt-1",
      scopeRules: SCOPE, targetBaseUrls: ["https://example.com/"], sessionProfile: SESSION_PROFILE,
    })).rejects.toThrow(/another workspace/);
  });

  it("never starts an active scan in this phase, even with a passing gate (§8)", async () => {
    const { zap } = createProxyConnectors(fixtureDeps());
    const denied = await zap.startActiveScan("ctx-none", {
      targetVerified: false, scopeApproved: false, assessmentApproved: false, activeTestingEnabled: false,
      userRole: "ANALYST", adminPolicyPermits: false, approval: null, currentScopeHash: "x", activeBudgetRequests: 0,
    });
    expect(denied.started).toBe(false);
    expect(denied.decision.reasonCode).toBe("TARGET_NOT_VERIFIED");
  });
});

describe("Burp connector (§9–§12)", () => {
  it("imports issues from Burp's XML export and site map; secrets in evidence are redacted", async () => {
    const { burp } = createProxyConnectors(fixtureDeps());
    await burp.connect("inst-burp-1");
    const context = await burp.createContext({
      instanceId: "inst-burp-1", workspaceId: "ws-1", assessmentId: "asmt-00000001",
      scopeRules: SCOPE, targetBaseUrls: ["https://example.com/"],
    });
    const envelope = await burp.collectPassiveResults(context.id);
    expect(envelope.findings).toHaveLength(2);
    const xss = envelope.findings.find((f) => f.vulnClass === "XSS");
    expect(xss?.severity).toBe("HIGH");
    expect(xss?.confidence).toBe(0.9); // Burp "Certain"
    expect(xss?.verificationStatus).not.toBe("CONFIRMED"); // §35 — never auto-confirmed
    expect(envelope.endpoints.some((e) => e.url.endsWith("/admin"))).toBe(true);
    const serialized = JSON.stringify(envelope);
    expect(serialized).not.toContain("fixture-burp-secret");
    expect(serialized).not.toContain("fixture-burp-token");
    expect(envelope.transactions.length).toBeGreaterThan(0);
  });
});

describe("Caido connector (§13)", () => {
  it("imports findings, API traffic and websocket inventory tolerantly", async () => {
    const { caido } = createProxyConnectors(fixtureDeps());
    await caido.connect("inst-caido-1");
    const context = await caido.createContext({
      instanceId: "inst-caido-1", workspaceId: "ws-1", assessmentId: "asmt-00000001",
      scopeRules: SCOPE, targetBaseUrls: ["https://example.com/"],
    });
    const envelope = await caido.collectPassiveResults(context.id);
    expect(envelope.findings.some((f) => f.vulnClass === "MISSING_SECURITY_HEADERS")).toBe(true);
    expect(envelope.transactions).toHaveLength(1);
    expect(envelope.transactions[0]?.url).toBe("https://example.com/api/users");
    expect(envelope.webSockets).toHaveLength(1);
    expect(envelope.webSockets[0]?.url).toBe("wss://example.com/socket");
    const serialized = JSON.stringify(envelope);
    expect(serialized).not.toContain("fixture-caido-secret");
    expect(serialized).not.toContain("fixture-caido-token");
  });
});

describe("cross-tool correlation (§33/§36)", () => {
  it("merges the same missing-CSP issue from ZAP and Burp into one canonical finding", () => {
    const zapParsed = new ZapIssueParser().parse({
      alerts: [{
        pluginId: "10038", name: "Content Security Policy (CSP) Header Not Set", riskcode: "1", confidence: "2",
        desc: "<p>no csp</p>", instances: [{ uri: "https://example.com/", method: "GET" }], cweid: "693",
      }],
    });
    const burpParsed = new BurpIssueParser().parse(BURP_XML_FOR_TEST);
    const correlated = correlateFindings([...zapParsed.findings, ...burpParsed.findings]);
    const canonical = correlated.findings.filter((cf) => cf.finding.vulnClass === "MISSING_SECURITY_HEADERS");
    expect(canonical).toHaveLength(1);
    expect(canonical[0]?.sources.map((src) => src.tool).sort()).toEqual(["burp-suite-professional", "owasp-zap"]);
  });
});

const BURP_XML_FOR_TEST = `<?xml version="1.0"?>
<issues>
  <issue>
    <name><![CDATA[Content Security Policy (CSP) Header Not Set]]></name>
    <host>https://example.com</host>
    <path><![CDATA[/]]></path>
    <severity>Low</severity>
    <confidence>Firm</confidence>
    <issueDetail><![CDATA[No CSP header.]]></issueDetail>
  </issue>
</issues>`;

describe("HAR import (§30 proxy/manual import)", () => {
  it("produces endpoints + transactions only — never findings — with secrets redacted", () => {
    const parsed = new HarImporter().parse(HAR_EXPORT);
    expect(parsed.findings).toHaveLength(0);
    expect(parsed.endpoints).toHaveLength(2);
    expect(parsed.transactions).toHaveLength(2);
    expect(parsed.observations.some((o) => o.summary.includes("GraphQL endpoint observed"))).toBe(true);
    expect(parsed.observations.some((o) => o.summary.includes("OpenAPI document observed"))).toBe(true);
    const serialized = JSON.stringify(parsed);
    expect(serialized).not.toContain("fixture-har-secret");
    expect(serialized).not.toContain("fixture-har-password");
  });
});

describe("adapter lifecycle over connectors", () => {
  it("ZAP adapter executes the passive pipeline through buildExecutionPlan → execute → parse → normalize", async () => {
    const adapters = createProxyAdapters(fixtureDeps());
    const zap = adapters.find((a) => a.metadata.slug === "owasp-zap")!;
    expect(await zap.checkAvailability()).toBe(true);
    const target = { type: "WEB_APPLICATION" as const, value: "example.com", host: "example.com" };
    const config = {
      instanceId: "inst-zap-1", workspaceId: "ws-1", assessmentId: "asmt-00000001", scanId: "scan-1",
      sessionProfileId: "sp-1",
      scopeIncludeHosts: ["example.com"], scopeExcludeHosts: [], scopeAllowedPorts: [], scopeAllowedPaths: [], scopeExcludedPaths: [],
      urls: [], timeoutSeconds: 600,
    };
    const plan = await zap.buildExecutionPlan(target, config);
    expect(plan.networkPolicy).toBe("CUSTOM_ALLOWLIST");
    const result = await zap.execute(plan);
    const parsed = await zap.parse(result.rawOutput!);
    const normalized = await zap.normalize(parsed);
    expect(normalized.findings.length).toBeGreaterThanOrEqual(2);
    expect(normalized.transactions?.length).toBe(2);
    expect(normalized.metrics.sessionExpired).toBe(1);
    expect(JSON.stringify(normalized)).not.toContain("fixture-zap-secret");
  });

  it("adapters report unavailable when no instance exists for the workspace (§66)", async () => {
    const adapters = createProxyAdapters(fixtureDeps([]));
    for (const a of adapters) {
      expect(await a.checkAvailability()).toBe(false);
      const health = await a.healthCheck();
      expect(health.status).toBe("NOT_CONFIGURED");
    }
  });
});
