import { describe, expect, it } from "vitest";
import { apiOperationPolicy, classifyMethod, graphqlOperationAutomatable } from "./policy";
import { inspectJwt, jwtFingerprint, JwtInspectionError } from "./jwt";
import { FIXTURE_JWT_BAD, FIXTURE_JWT_GOOD, FIXTURE_JWT_LONG_LIVED, makeFakeJwt } from "./fixtures";
import { owaspApiCategoryFor, OWASP_API_TAXONOMY_VERSION } from "./taxonomy";
import { clampDiscoveryBudget, ADMIN_DISCOVERY_CAPS } from "../recon/budget";
import type { ApiOperation } from "./types";

const op = (method: string, path: string, extra: Partial<ApiOperation> = {}): ApiOperation => ({ method, path, source: "test", ...extra });

/**
 * API operation policy + JWT inspection (Prompt 9 §16–§17, §22–§25,
 * §30, §47–§50, §70, §75). The safety posture is the product: these
 * tests prove the default baseline cannot execute state-changing,
 * destructive, financial, upload or authentication-abuse operations,
 * and that JWT analysis is inspection-only with the raw token never
 * present in any produced record.
 */
describe("ApiOperationPolicyEngine (§16/§17)", () => {
  it("classifies safe read methods as SAFE and automatable", () => {
    for (const m of ["GET", "HEAD", "OPTIONS"]) {
      expect(classifyMethod(m)).toBe("SAFE_READ");
      const v = apiOperationPolicy.classify(op(m, "/users"));
      expect(v.classification).toBe("SAFE");
      expect(v.automatable).toBe(true);
    }
  });

  it("blocks POST/PUT/PATCH by default; explicit approval admits STATE_CHANGING only", () => {
    for (const m of ["POST", "PUT", "PATCH"]) {
      const v = apiOperationPolicy.classify(op(m, "/users", { hasRequestBody: true }));
      expect(v.classification).toBe("STATE_CHANGING");
      expect(v.automatable).toBe(false);
      expect(apiOperationPolicy.classify(op(m, "/users"), { allowStateChanging: true }).automatable).toBe(true);
    }
  });

  it("treats DELETE as destructive-unknown: denied by default, and NOT admitted by allowStateChanging", () => {
    const v = apiOperationPolicy.classify(op("DELETE", "/users/{id}"));
    expect(v.classification).toBe("DESTRUCTIVE_UNKNOWN");
    expect(v.automatable).toBe(false);
    expect(apiOperationPolicy.classify(op("DELETE", "/users/{id}"), { allowStateChanging: true }).automatable).toBe(false);
    // Only the dedicated DELETE workflow flag admits it (§48).
    expect(apiOperationPolicy.classify(op("DELETE", "/users/{id}"), { allowDelete: true }).automatable).toBe(true);
  });

  it("never automates unknown methods or destructive paths", () => {
    expect(apiOperationPolicy.classify(op("PROPFIND", "/x")).classification).toBe("DESTRUCTIVE_UNKNOWN");
    expect(apiOperationPolicy.classify(op("POST", "/admin/purge")).classification).toBe("DESTRUCTIVE_UNKNOWN");
    expect(apiOperationPolicy.classify(op("GET", "/users/delete")).classification).toBe("DESTRUCTIVE_UNKNOWN");
  });

  it("classifies upload, financial and auth-mutation routes REVIEW_REQUIRED (§47/§49/§50)", () => {
    expect(apiOperationPolicy.classify(op("POST", "/files/upload")).classification).toBe("REVIEW_REQUIRED");
    expect(apiOperationPolicy.classify(op("POST", "/payments/checkout")).classification).toBe("REVIEW_REQUIRED");
    expect(apiOperationPolicy.classify(op("GET", "/payments/refund")).classification).toBe("REVIEW_REQUIRED");
    expect(apiOperationPolicy.classify(op("POST", "/auth/login")).classification).toBe("REVIEW_REQUIRED");
    expect(apiOperationPolicy.classify(op("POST", "/auth/password-reset")).classification).toBe("REVIEW_REQUIRED");
    // REVIEW_REQUIRED never becomes automatable via the state-changing flag.
    expect(apiOperationPolicy.classify(op("POST", "/payments/checkout"), { allowStateChanging: true }).automatable).toBe(false);
  });

  it("partitions operations for a run and keeps reasons auditable", () => {
    const { allowed, blocked } = apiOperationPolicy.partition([
      op("GET", "/users"), op("POST", "/users"), op("DELETE", "/users/{id}"), op("GET", "/health"),
    ]);
    expect(allowed.map((a) => a.op.path)).toEqual(["/users", "/health"]);
    expect(blocked.map((b) => b.op.path)).toEqual(["/users", "/users/{id}"]);
    expect(blocked.every((b) => b.verdict.reasons.length > 0)).toBe(true);
  });

  it("administrator overrides apply but cannot widen DELETE without its flag (§17)", () => {
    const v = apiOperationPolicy.classify(op("DELETE", "/test/reset"), { overrides: { "DELETE /test/reset": "STATE_CHANGING" } });
    expect(v.classification).toBe("STATE_CHANGING");
    expect(v.automatable).toBe(false);
    // Tightening always works.
    expect(apiOperationPolicy.classify(op("GET", "/admin"), { overrides: { "GET /admin": "REVIEW_REQUIRED" } }).automatable).toBe(false);
  });

  it("GraphQL mutations/subscriptions are never automatable; queries are reads (§30)", () => {
    expect(graphqlOperationAutomatable("QUERY")).toBe(true);
    expect(graphqlOperationAutomatable("MUTATION")).toBe(false);
    expect(graphqlOperationAutomatable("SUBSCRIPTION")).toBe(false);
  });
});

describe("JwtInspector (§22–§25, §70)", () => {
  it("accepts a well-configured token with zero findings", () => {
    const r = inspectJwt(FIXTURE_JWT_GOOD, { source: "test" });
    expect(r.findings).toEqual([]);
    expect(r.profile.algorithm).toBe("RS256");
    expect(r.profile.fingerprint).toBe(jwtFingerprint(FIXTURE_JWT_GOOD));
    expect(r.profile.issuer).toBe("https://auth.example.com");
    expect(r.profile.lifetimeSeconds).toBe(3660);
  });

  it("flags none-alg, missing expiry and sensitive claims — with redaction", () => {
    const r = inspectJwt(FIXTURE_JWT_BAD, { source: "test" });
    const classes = r.findings.map((f) => f.vulnClass);
    expect(classes).toContain("JWT_ALGORITHM_CONFIGURATION");
    expect(classes).toContain("JWT_MISSING_EXPIRY");
    expect(classes).toContain("JWT_SENSITIVE_CLAIMS");
    expect(r.findings.find((f) => f.vulnClass === "JWT_ALGORITHM_CONFIGURATION")!.severity).toBe("HIGH");
    expect(r.profile.claimsSummary.password).toBe("REDACTED");
  });

  it("flags excessive lifetime against policy", () => {
    const r = inspectJwt(FIXTURE_JWT_LONG_LIVED, { source: "test" });
    expect(r.findings.map((f) => f.vulnClass)).toContain("JWT_EXCESSIVE_LIFETIME");
    // HS256 alone is an observation, NOT a vulnerability (§24).
    expect(r.findings.map((f) => f.vulnClass)).not.toContain("JWT_ALGORITHM_CONFIGURATION");
    expect(r.observations.some((o) => o.includes("HS256"))).toBe(true);
  });

  it("checks issuer/audience consistency only when policy configures them", () => {
    const r = inspectJwt(FIXTURE_JWT_GOOD, { source: "test", policy: { expectedIssuer: "https://other.example.com", expectedAudience: "other-api" } });
    expect(r.findings.filter((f) => f.vulnClass === "JWT_ISSUER_AUDIENCE_MISMATCH")).toHaveLength(2);
    const ok = inspectJwt(FIXTURE_JWT_GOOD, { source: "test", policy: { expectedIssuer: "https://auth.example.com", expectedAudience: "zerosweep-test-api" } });
    expect(ok.findings).toEqual([]);
  });

  it("the raw token NEVER appears in any produced record (§25/§65)", () => {
    for (const token of [FIXTURE_JWT_GOOD, FIXTURE_JWT_BAD, FIXTURE_JWT_LONG_LIVED]) {
      const serialized = JSON.stringify(inspectJwt(token, { source: "test" }));
      expect(serialized).not.toContain(token);
      expect(serialized).not.toContain(token.split(".")[1]);
      expect(serialized).not.toContain("FAKE-test-password-not-real");
    }
  });

  it("rejects malformed tokens deterministically", () => {
    expect(() => inspectJwt("not-a-jwt", { source: "t" })).toThrow(JwtInspectionError);
    expect(() => inspectJwt("a.b", { source: "t" })).toThrow(JwtInspectionError);
    expect(() => inspectJwt(`${"x".repeat(9000)}.b.c`, { source: "t" })).toThrow(JwtInspectionError);
    expect(() => inspectJwt(makeFakeJwt({ alg: "RS256" }, [1, 2] as never), { source: "t" })).toThrow(JwtInspectionError);
  });

  it("identifiers in claims are truncated, never stored raw", () => {
    const r = inspectJwt(FIXTURE_JWT_GOOD, { source: "t" });
    expect(String(r.profile.claimsSummary.sub)).toContain("REDACTED");
    expect(JSON.stringify(r.profile.claimsSummary)).not.toContain("test-user-a");
  });
});

describe("OWASP API taxonomy (§41)", () => {
  it("is versioned and maps only confident API classes", () => {
    expect(OWASP_API_TAXONOMY_VERSION).toBe("OWASP API Security Top 10 2023");
    expect(owaspApiCategoryFor("JWT_MISSING_EXPIRY")).toBe("API2:2023 Broken Authentication");
    expect(owaspApiCategoryFor("EXPOSED_API_DOCUMENTATION")).toBe("API8:2023 Security Misconfiguration");
    expect(owaspApiCategoryFor("API_RESPONSE_CONFORMANCE")).toBeUndefined();
    expect(owaspApiCategoryFor("SQL_INJECTION")).toBeUndefined();
  });
});

describe("API discovery budget (§61)", () => {
  it("carries the API ceilings with hard admin caps", () => {
    const b = clampDiscoveryBudget();
    expect(b.maxApiRequests).toBe(5_000);
    expect(b.maxSpecSize).toBe(5 * 1024 * 1024);
    expect(b.maxJwtTokensAnalyzed).toBe(50);
    const clamped = clampDiscoveryBudget({ maxApiRequests: 10_000_000, maxSpecSize: 100_000_000 });
    expect(clamped.maxApiRequests).toBe(ADMIN_DISCOVERY_CAPS.maxApiRequests);
    expect(clamped.maxSpecSize).toBe(ADMIN_DISCOVERY_CAPS.maxSpecSize);
  });
});
