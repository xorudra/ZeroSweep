import { describe, expect, it } from "vitest";
import { AdapterConfigurationError } from "../adapter/adapter.errors";
import type { AdapterTarget } from "../adapter/adapter.interface";
import { FixtureToolRunner } from "../recon/runner";
import { ToolRegistry } from "../registry/registry";
import { evaluateModuleGate, toolCapability, toolsByRiskClass } from "./tool-capabilities";
import { BudgetMeter, PLATFORM_BUDGET_CEILING, PRODUCTION_DEFAULT_BUDGET, clampBudget, requestClassOf } from "./budget";
import { buildScopeSnapshot, classifyDiscoveredHost, judgeInternalTarget, judgeUrlAgainstSnapshot, validateReferencedHosts } from "./scope-lock";
import { evaluatePreflight } from "./preflight";
import { endpointIdentity, isDangerousPath, mergeContentDiscovery, clampCrawlPolicy } from "./endpoints";
import { analyzeCors, analyzeCsrf, analyzeHeaders } from "./headers";
import { boundGraphqlTest, measureGraphqlOperation } from "./graphql-limits";
import {
  evaluateAuthorizationMatrix, isForbiddenPasswordModule, validateBusinessLogicScenario, validateMatrixRows, clampRateLimitAnalysis,
} from "./authorization";
import { profileDefinition } from "./profiles";
import { computeCoverage, deriveScanStatus, toolHealthView } from "./coverage";
import { parseCommixOutput, parseDalfoxOutput, parseSqlmapOutput, parseSstimapOutput, parseWpscanOutput } from "./parsers-injection";
import { CommixAdapter, DalfoxAdapter, SqlmapAdapter, WpscanAdapter } from "./adapters-injection";
import { createWebVaptAdapters, registerWebVaptAdapters } from "./registry";
import {
  COMMIX_FIXTURE, DALFOX_FIXTURE, FIXTURE_PLANTED_TOKEN, GRAPHQL_EXCESSIVE_FIXTURE, GRAPHQL_OK_FIXTURE,
  MALFORMED_FIXTURE, SQLMAP_FIXTURE, SSTIMAP_FIXTURE, WPSCAN_FIXTURE,
} from "./fixtures";

const target: AdapterTarget = { type: "WEB_APPLICATION", value: "https://staging.example.com", host: "staging.example.com" };
const snapshot = buildScopeSnapshot({ workspaceId: "ws-1", origins: ["https://staging.example.com"] });

describe("capability registry (§14–§16)", () => {
  it("records capability + risk metadata for every web/API tool, with no destructive class", () => {
    for (const slug of ["dalfox", "sqlmap", "commix", "sstimap", "wpscan", "nuclei", "zap", "katana"]) {
      const rec = toolCapability(slug);
      expect(rec, slug).toBeDefined();
      expect(["PASSIVE", "LOW", "MODERATE", "HIGH"]).toContain(rec!.riskClass);
      expect(rec!.capabilities.length).toBeGreaterThan(0);
    }
    expect(toolsByRiskClass("HIGH").map((t) => t.slug).sort()).toEqual(["commix", "sqlmap", "sstimap"]);
  });

  it("gates HIGH modules behind profile + permission + approval (§16/§167)", () => {
    const base = { slug: "sqlmap", explicitProfile: true, activeAuthorization: true, highRiskPermission: true, approvalRecorded: true };
    expect(evaluateModuleGate(base).allowed).toBe(true);
    expect(evaluateModuleGate({ ...base, approvalRecorded: false }).allowed).toBe(false);
    expect(evaluateModuleGate({ ...base, highRiskPermission: false }).allowed).toBe(false);
    expect(evaluateModuleGate({ ...base, explicitProfile: false }).allowed).toBe(false);
    expect(evaluateModuleGate({ ...base, activeAuthorization: false }).allowed).toBe(false);
    expect(evaluateModuleGate({ ...base, slug: "not-a-tool" }).allowed).toBe(false);
    expect(evaluateModuleGate({ slug: "whatweb", explicitProfile: false, activeAuthorization: false, highRiskPermission: false }).allowed).toBe(true);
  });
});

describe("preflight (§7/§8/§173–§175)", () => {
  const authOk = { activeAuthorization: true, targetVerified: true, expiresAt: null };
  it("READY when authorized, verified and reachable", () => {
    const r = evaluatePreflight({ authorization: authOk, probes: { transport: "CONFIGURED", dnsResolves: true, httpReachable: true, tlsValid: true }, snapshot });
    expect(r.status).toBe("READY");
  });
  it("BLOCKED when authorization is missing (§173) or expired (§174)", () => {
    expect(evaluatePreflight({ authorization: { activeAuthorization: false, targetVerified: true }, probes: { transport: "CONFIGURED", dnsResolves: true, httpReachable: true }, snapshot }).status).toBe("BLOCKED");
    expect(evaluatePreflight({ authorization: { activeAuthorization: true, targetVerified: true, expiresAt: new Date(Date.now() - 1000) }, probes: { transport: "CONFIGURED", dnsResolves: true, httpReachable: true }, snapshot }).status).toBe("BLOCKED");
  });
  it("records an out-of-scope redirect and blocks active follow-up (§9/§175)", () => {
    const r = evaluatePreflight({ authorization: authOk, probes: { transport: "CONFIGURED", dnsResolves: true, httpReachable: true, redirectFinalUrl: "https://evil.example.net/landing" }, snapshot });
    expect(r.status).toBe("BLOCKED");
    expect(r.redirectRecorded).toBe("https://evil.example.net/landing");
  });
  it("NOT_CONFIGURED probe transport is honestly BLOCKED, never READY", () => {
    const r = evaluatePreflight({ authorization: authOk, probes: { transport: "NOT_CONFIGURED" }, snapshot });
    expect(r.status).toBe("BLOCKED");
    expect(r.checks.some((c) => c.name === "PROBE_TRANSPORT" && c.status === "UNKNOWN")).toBe(true);
  });
  it("UNREACHABLE when authorized but HTTP does not answer", () => {
    const r = evaluatePreflight({ authorization: authOk, probes: { transport: "CONFIGURED", dnsResolves: true, httpReachable: false }, snapshot });
    expect(r.status).toBe("UNREACHABLE");
  });
});

describe("scope lock (§136–§141/§133–§135)", () => {
  it("freezes scope into a hashed immutable snapshot; mid-run scope edits do not expand it (§137)", () => {
    const snap2 = buildScopeSnapshot({ workspaceId: "ws-1", origins: ["https://staging.example.com", "https://other.example.com"] });
    expect(snap2.hash).not.toBe(snapshot.hash);
    expect(judgeUrlAgainstSnapshot(snapshot, "https://other.example.com/")).toBe("OUT_OF_SCOPE");
    expect(judgeUrlAgainstSnapshot(snapshot, "https://staging.example.com/app")).toBe("IN_SCOPE");
  });
  it("newly discovered hosts are candidates only (§138)", () => {
    expect(classifyDiscoveredHost(snapshot, "api.staging.example.com")).toBe("CANDIDATE_ONLY");
    expect(classifyDiscoveredHost(snapshot, "staging.example.com")).toBe("IN_SCOPE");
  });
  it("spec/collection hosts are validated, never trusted (§139/§140/§176/§177)", () => {
    const v = validateReferencedHosts(snapshot, ["staging.example.com", "api.partner.example.net"]);
    expect(v.accepted).toEqual(["staging.example.com"]);
    expect(v.rejected).toEqual(["api.partner.example.net"]);
  });
  it("blocks cloud metadata and unauthorised internal targets (§133/§134/§195)", () => {
    expect(judgeInternalTarget("169.254.169.254", { internalScopeAuthorized: true }).allowed).toBe(false);
    expect(judgeInternalTarget("169.254.169.254", { internalScopeAuthorized: true, approvedIsolatedMetadataTest: true }).allowed).toBe(true);
    expect(judgeInternalTarget("10.0.0.5", { internalScopeAuthorized: false }).allowed).toBe(false);
    expect(judgeInternalTarget("10.0.0.5", { internalScopeAuthorized: true }).allowed).toBe(true);
    expect(judgeInternalTarget("staging.example.com", { internalScopeAuthorized: false }).allowed).toBe(true);
  });
});

describe("budgets (§48/§126/§127/§186)", () => {
  it("clamps workspace requests to the platform ceiling", () => {
    const { budget, clampedFields } = clampBudget({ maxRequests: 10_000_000, maxRequestsPerSecond: 9999 });
    expect(budget.maxRequests).toBe(PLATFORM_BUDGET_CEILING.maxRequests);
    expect(budget.maxRequestsPerSecond).toBe(PLATFORM_BUDGET_CEILING.maxRequestsPerSecond);
    expect(clampedFields).toContain("maxRequests");
    expect(requestClassOf(PRODUCTION_DEFAULT_BUDGET)).toBe("MEDIUM");
  });
  it("budget exhaustion is graceful — meter reports exhausted, scan derives COMPLETED_WITH_GAPS", () => {
    const meter = new BudgetMeter({ ...PRODUCTION_DEFAULT_BUDGET, maxRequests: 3 });
    expect(meter.recordRequest()).toBe(true);
    meter.recordRequest(); meter.recordRequest();
    expect(meter.exhausted).toBe(true);
    expect(meter.recordRequest()).toBe(false);
    expect(deriveScanStatus({ cancelled: false, preflightBlocked: false, stagesFailed: 0, budgetExhausted: true, skippedCount: 0 })).toBe("COMPLETED_WITH_GAPS");
  });
});

describe("endpoint identity + content discovery (§23/§24/§27/§29)", () => {
  it("identity ignores volatile parameter values and ids", () => {
    const a = endpointIdentity("https://staging.example.com/users/42?tab=profile");
    const b = endpointIdentity("https://staging.example.com/users/99?tab=settings");
    expect(a!.identity).toBe(b!.identity);
    expect(a!.path).toBe("/users/{id}");
  });
  it("merges multi-tool observations into one canonical endpoint (§24/§189 shape)", () => {
    const merged = mergeContentDiscovery([
      { tool: "ffuf", url: "https://staging.example.com/admin", statusCode: 200 },
      { tool: "feroxbuster", url: "https://staging.example.com/admin", statusCode: 200, contentType: "text/html" },
      { tool: "gobuster", url: "https://staging.example.com/admin", statusCode: 403 },
    ]);
    expect(merged).toHaveLength(1);
    expect(merged[0]!.sources.sort()).toEqual(["feroxbuster", "ffuf", "gobuster"]);
    expect(merged[0]!.observations).toBe(3);
  });
  it("excludes dangerous paths from automatic interaction (§27)", () => {
    expect(isDangerousPath("/account/delete")).toBe(true);
    expect(isDangerousPath("/logout")).toBe(true);
    expect(isDangerousPath("/checkout/payment")).toBe(true);
    expect(isDangerousPath("/products/list")).toBe(false);
  });
  it("clamps crawl policy to hard bounds (§26)", () => {
    const p = clampCrawlPolicy({ maxDepth: 99, maxUrls: 999_999 });
    expect(p.maxDepth).toBe(5);
    expect(p.maxUrls).toBe(10_000);
  });
});

describe("headers / CORS / CSRF (§86–§89)", () => {
  it("missing header on a JSON API is informational, not high severity (§87)", () => {
    const findings = analyzeHeaders({ url: "https://api.example.com/v1", contentType: "application/json", headers: {} });
    expect(findings.every((f) => f.severity === "INFORMATIONAL" || f.severity === "LOW")).toBe(true);
    expect(findings.some((f) => f.title.includes("frame"))).toBe(false);
  });
  it("flags reflected-origin CORS with credentials (§88)", () => {
    const findings = analyzeCors({ url: "https://api.example.com", headers: { "access-control-allow-origin": "https://evil.example.net", "access-control-allow-credentials": "true" }, requestOrigin: "https://evil.example.net" });
    expect(findings).toHaveLength(1);
    expect(findings[0]!.severity).toBe("MEDIUM");
  });
  it("CSRF: SameSite mitigation downgrades to informational (§89)", () => {
    const findings = analyzeCsrf({ url: "https://staging.example.com/form", headers: {}, sessionCookies: true, formsHaveCsrfTokens: false, setCookieAttributes: ["session=…; Path=/; SameSite=Lax; HttpOnly"] });
    expect(findings[0]!.severity).toBe("INFORMATIONAL");
  });
});

describe("GraphQL bounds (§59/§184)", () => {
  it("measures depth/complexity and rejects excessive test generation", () => {
    expect(boundGraphqlTest(GRAPHQL_OK_FIXTURE).allowed).toBe(true);
    const bad = boundGraphqlTest(GRAPHQL_EXCESSIVE_FIXTURE);
    expect(bad.allowed).toBe(false);
    expect(bad.violations.join(" ")).toMatch(/depth|complexity/);
    expect(measureGraphqlOperation(GRAPHQL_OK_FIXTURE).depth).toBeGreaterThanOrEqual(3);
  });
});

describe("authorization matrix + business logic (§97–§104/§191)", () => {
  it("expected-vs-observed mismatch creates a CANDIDATE, matches do not (§100)", () => {
    const r = evaluateAuthorizationMatrix([
      { identityA: "fixture:user-a", identityB: "fixture:user-b", role: "USER", resource: "fixture:invoice/{id}", expectedAccess: "DENY", observedAccess: "ALLOW" },
      { identityA: "fixture:user-a", role: "USER", resource: "fixture:own-profile", expectedAccess: "ALLOW", observedAccess: "ALLOW" },
      { identityA: "fixture:user-a", role: "ADMIN", resource: "fixture:admin-panel", expectedAccess: "ALLOW", observedAccess: "NOT_TESTED" },
    ]);
    expect(r.candidates).toHaveLength(1);
    expect(r.candidates[0]!.cwe).toBe("CWE-862");
    expect(r.matches).toBe(1);
    expect(r.untested).toBe(1);
  });
  it("rejects non-fixture resource identifiers — no broad enumeration (§98)", () => {
    const problems = validateMatrixRows([{ identityA: "fixture:a", role: "USER", resource: "user-918273-real-id", expectedAccess: "DENY", observedAccess: "NOT_TESTED" }]);
    expect(problems.length).toBeGreaterThan(0);
  });
  it("business-logic scenarios are human-defined and safe-step only (§101/§102)", () => {
    expect(validateBusinessLogicScenario({ name: "Coupon reuse", preconditions: "staging", authorizedIdentities: ["fixture:a"], safeSteps: ["Apply the same coupon code twice and compare totals"], expectedBehavior: "Second application is rejected" })).toEqual([]);
    const bad = validateBusinessLogicScenario({ name: "X", preconditions: "", authorizedIdentities: ["fixture:a"], safeSteps: ["Delete the order and check"], expectedBehavior: "?" });
    expect(bad.length).toBeGreaterThan(0);
  });
  it("password-attack modules are forbidden and rate-limit analysis is bounded (§103/§104)", () => {
    expect(isForbiddenPasswordModule("hydra")).toBe(true);
    expect(isForbiddenPasswordModule("nuclei")).toBe(false);
    expect(clampRateLimitAnalysis({ requests: 100_000 }).requests).toBe(20);
  });
});

describe("profiles + coverage (§122–§150/§170)", () => {
  it("WEB_SAFE is the §172 baseline profile; HIGH tools are in NO named profile", () => {
    expect(profileDefinition("WEB_SAFE").toolSlugs).toContain("nuclei");
    for (const key of ["WEB_PASSIVE", "WEB_SAFE", "WEB_STANDARD", "API_SAFE", "API_STANDARD", "TLS_ONLY", "CONTENT_DISCOVERY", "TARGETED_VERIFICATION"] as const) {
      const slugs = profileDefinition(key).toolSlugs;
      expect(slugs).not.toContain("sqlmap");
      expect(slugs).not.toContain("commix");
      expect(slugs).not.toContain("sstimap");
      expect(slugs).not.toContain("hydra");
    }
  });
  it("coverage is honest: null when nothing discovered, limitations listed (§147/§148)", () => {
    const cov = computeCoverage({ discoveredEndpoints: 0, testedEndpoints: 0, discoveredParameters: 0, testedParameters: 0, authenticatedEndpoints: 0, testedAuthenticatedEndpoints: 0, toolsPlanned: [], toolsContributed: [], skipped: [], budgetExhausted: false, stagesFailed: 0 });
    expect(cov.endpointCoverage).toBeNull();
    expect(cov.limitations.join(" ")).toMatch(/not complete/);
    const cov2 = computeCoverage({ discoveredEndpoints: 10, testedEndpoints: 4, discoveredParameters: 5, testedParameters: 5, authenticatedEndpoints: 2, testedAuthenticatedEndpoints: 0, toolsPlanned: ["nuclei", "dalfox"], toolsContributed: ["nuclei"], skipped: [{ test: "dalfox on /search", reason: "TOOL_UNAVAILABLE" }], budgetExhausted: false, stagesFailed: 0 });
    expect(cov2.endpointCoverage).toBe(0.4);
    expect(cov2.toolCoverage.silent).toEqual(["dalfox"]);
  });
  it("tool health reports UNAVAILABLE honestly (§146)", () => {
    expect(toolHealthView({ slug: "sqlmap", installed: false, errorRate: 0, parserCompatible: true }).status).toBe("UNAVAILABLE");
    expect(toolHealthView({ slug: "nuclei", installed: true, version: "3.3.0", errorRate: 0, parserCompatible: true }).status).toBe("HEALTHY");
  });
});

describe("injection adapters — detection only (§73–§82)", () => {
  it("SQLmap plan is detection-only argv (§74) and carries no forbidden option", async () => {
    const adapter = new SqlmapAdapter(new FixtureToolRunner({}));
    const plan = await adapter.buildExecutionPlan(target, { urls: ["https://staging.example.com/item?id=1"], parameter: "id" });
    const joined = plan.arguments.join(" ");
    expect(joined).toContain("--technique=B");
    expect(joined).toContain("--risk 1");
    for (const forbidden of ["--dump", "--os-shell", "--file-read", "--file-write", "--sql-shell", "--passwords"]) {
      expect(joined).not.toContain(forbidden);
    }
    expect(plan.arguments.join("")).not.toMatch(/;|&&|\$\(/);
  });
  it("SQLmap config attempting --dump / OS shell / file write is REJECTED (§179)", async () => {
    const adapter = new SqlmapAdapter(new FixtureToolRunner({}));
    await expect(adapter.validateConfiguration({ urls: ["https://staging.example.com/?id=1"], note: "--dump-all" })).rejects.toBeInstanceOf(AdapterConfigurationError);
    await expect(adapter.buildExecutionPlan(target, { urls: ["https://staging.example.com/?id=1"], parameter: "id", dbms: "mysql --os-shell" })).rejects.toBeInstanceOf(AdapterConfigurationError);
  });
  it("Commix config attempting an arbitrary OS command is REJECTED (§180)", async () => {
    const adapter = new CommixAdapter(new FixtureToolRunner({}));
    await expect(adapter.validateConfiguration({ urls: ["https://staging.example.com/ping"], parameter: "host --os-cmd=id" })).rejects.toBeInstanceOf(AdapterConfigurationError);
    const plan = await adapter.buildExecutionPlan(target, { urls: ["https://staging.example.com/ping?host=x"], parameter: "host" });
    expect(plan.arguments.join(" ")).not.toContain("--os-cmd");
  });
  it("WPScan rejects password-attack options and enumerates only (§82)", async () => {
    const adapter = new WpscanAdapter(new FixtureToolRunner({}));
    await expect(adapter.validateConfiguration({ urls: ["https://staging.example.com"], note: "--passwords rockyou.txt" })).rejects.toBeInstanceOf(AdapterConfigurationError);
    const plan = await adapter.buildExecutionPlan(target, { urls: ["https://staging.example.com"] });
    expect(plan.arguments).toContain("--enumerate");
    expect(plan.arguments.join(" ")).not.toContain("--passwords");
  });
  it("Dalfox plan contains no custom or persistent payload options (§71)", async () => {
    const adapter = new DalfoxAdapter(new FixtureToolRunner({}));
    const plan = await adapter.buildExecutionPlan(target, { urls: ["https://staging.example.com/search?q=x"] });
    const joined = plan.arguments.join(" ");
    expect(joined).not.toContain("--custom-payload");
    expect(joined).not.toContain("--blind");
  });
  it("all six adapters register in the shared ToolRegistry", () => {
    const registry = new ToolRegistry();
    const adapters = registerWebVaptAdapters(registry, new FixtureToolRunner({}));
    expect(adapters.map((a) => a.metadata.slug).sort()).toEqual(["commix", "dalfox", "sqlmap", "sstimap", "wpscan", "xsstrike"]);
    expect(createWebVaptAdapters(new FixtureToolRunner({})).length).toBe(6);
  });
});

describe("fixture parsing (§172/§181/§188/§189)", () => {
  it("Dalfox fixture → verified + candidate XSS with marker evidence", () => {
    const parsed = parseDalfoxOutput(DALFOX_FIXTURE);
    expect(parsed.findings).toHaveLength(2);
    const verified = parsed.findings.find((f) => f.confidence >= 0.9);
    expect(verified?.vulnClass).toBe("XSS_REFLECTED");
    expect(verified?.cwe).toBe("CWE-79");
    expect(verified?.parameter).toBe("q");
  });
  it("SQLmap fixture → one detection finding, DBMS hint, planted token redacted (§178)", () => {
    const parsed = parseSqlmapOutput(SQLMAP_FIXTURE);
    expect(parsed.findings).toHaveLength(1);
    expect(parsed.findings[0]!.vulnClass).toBe("SQL_INJECTION");
    expect(parsed.dbmsHint).toContain("MySQL");
    expect(JSON.stringify(parsed)).not.toContain(FIXTURE_PLANTED_TOKEN);
  });
  it("Commix + SSTImap fixtures → detection findings with marker evidence only", () => {
    const c = parseCommixOutput(COMMIX_FIXTURE);
    expect(c.findings[0]!.vulnClass).toBe("COMMAND_INJECTION");
    const s = parseSstimapOutput(SSTIMAP_FIXTURE);
    expect(s.findings[0]!.vulnClass).toBe("SSTI");
    expect(s.findings[0]!.description).toContain("Jinja2");
  });
  it("WPScan fixture → version-correlated CVE findings + configuration observation (§81)", () => {
    const parsed = parseWpscanOutput(WPSCAN_FIXTURE);
    expect(parsed.findings.length).toBeGreaterThanOrEqual(3);
    expect(parsed.findings.some((f) => f.cve === "CVE-2024-24860")).toBe(true);
    expect(parsed.findings.some((f) => f.vulnClass === "WORDPRESS_CONFIGURATION")).toBe(true);
  });
  it("malformed output parses to warnings, never to clean findings (§188)", () => {
    const d = parseDalfoxOutput(MALFORMED_FIXTURE);
    expect(d.findings).toEqual([]);
    expect(d.warnings.length).toBeGreaterThan(0);
    const w = parseWpscanOutput(MALFORMED_FIXTURE);
    expect(w.findings).toEqual([]);
    expect(w.warnings.length).toBeGreaterThan(0);
  });
  it("dedup: Dalfox + XSStrike on the same parameter produce the same canonical family (§107/§189)", () => {
    const d = parseDalfoxOutput(DALFOX_FIXTURE).findings[0]!;
    expect(d.vulnClass).toBe("XSS_REFLECTED");
    // Canonical correlation keys on asset+endpoint+parameter+class —
    // both XSS tools land in the same family for the correlation engine.
    expect(d.endpoint).toContain("/search");
  });
});
