import { describe, expect, it } from "vitest";
import { createHash } from "node:crypto";
const sha256Hex = (v: string): string => createHash("sha256").update(v).digest("hex");
import { evaluateActiveScanGate, evaluateApproval, hashScopeSnapshot, type ScanApprovalRecord } from "./approval";
import { ADMIN_PROXY_CAPS, clampConnectorRateLimits, clampProxyBudget, DEFAULT_PROXY_BUDGET } from "./budget";
import { classifyApiKind, classifyFormSafety, isGraphQlEndpoint, isLogoutUrl, isOpenApiDocumentUrl } from "./classify";
import {
  ImportValidationError, MAX_IMPORT_BYTES, assertImportSize, assertXmlSafe, parseImportJson, parseXmlDocument, xmlChildren,
} from "./import-security";
import { HttpEvidenceRedactor } from "./redactor";
import { mapBurpConfidence, mapBurpSeverity, mapCaidoSeverity, mapZapConfidence, mapZapSeverity } from "./severity";
import { ENDPOINT_REFERENCE_PATTERN, validateEndpointReference } from "./types";
import { assertScannerEndpointAllowed } from "./connector";
import type { ScopeRules } from "@zerosweep/validation";

const SCOPE: ScopeRules = {
  includeHosts: ["example.com"], excludeHosts: [], includeCidrs: [],
  allowedPorts: [], allowedPaths: [], excludedPaths: [],
};

describe("endpoint references (§16/§17)", () => {
  it("accepts opaque references and rejects anything URL-shaped", () => {
    expect(ENDPOINT_REFERENCE_PATTERN.test("ZAP_DAEMON_PROD")).toBe(true);
    expect(validateEndpointReference("ZAP_DAEMON_PROD")).toEqual({ ok: true });
    for (const bad of ["https://zap.internal:8080", "zap.internal", "10.0.0.5", "169.254.169.254", "zap daemon", ""]) {
      expect(validateEndpointReference(bad).ok, bad).toBe(false);
    }
  });
});

describe("scanner endpoint SSRF guard (§71)", () => {
  it("always rejects loopback, link-local and metadata — even when internal-approved", () => {
    expect(() => assertScannerEndpointAllowed("https://127.0.0.1:8443", true)).toThrow(/loopback/);
    expect(() => assertScannerEndpointAllowed("https://169.254.169.254", true)).toThrow(/link-local/);
    expect(() => assertScannerEndpointAllowed("https://[::1]:8443", true)).toThrow(/loopback/);
    expect(() => assertScannerEndpointAllowed("http://metadata.google.internal", true)).toThrow(/metadata/);
  });
  it("rejects private ranges unless the deployment is approved internal", () => {
    expect(() => assertScannerEndpointAllowed("https://10.1.2.3:8443")).toThrow(/approved internal/);
    expect(assertScannerEndpointAllowed("https://10.1.2.3:8443", true)).toContain("10.1.2.3");
    expect(() => assertScannerEndpointAllowed("https://scanner-user:secret@zap.example.com")).toThrow(/must not embed credentials/);
    expect(assertScannerEndpointAllowed("https://zap.example.com:8443")).toContain("zap.example.com");
  });
});

describe("HTTP evidence redaction (§27–§29)", () => {
  const redactor = new HttpEvidenceRedactor();
  it("redacts sensitive headers case-insensitively and keeps the rest visible", () => {
    const out = redactor.redactHttpMessage("GET / HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer abc123\r\ncookie: session=x\r\nX-API-Key: k\r\nX-Custom: keep\r\n\r\n", "text/html");
    expect(out.text).not.toContain("abc123");
    expect(out.text).not.toContain("session=x");
    expect(out.text).toContain("X-Custom: keep");
    expect(out.text).toContain("[REDACTED]");
    expect(out.checksum).toBe(sha256Hex("GET / HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer abc123\r\ncookie: session=x\r\nX-API-Key: k\r\nX-Custom: keep\r\n\r\n"));
    expect(out.redacted).toBe(true);
  });
  it("redacts JSON bodies by key, including nested tokens", () => {
    const out = redactor.redactHttpMessage("POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/json\r\n\r\n" + '{"user":"rudra","creds":{"access_token":"tok-1","nested":{"password":"pw"}},"ok":1}');
    expect(out.text).not.toContain("tok-1");
    expect(out.text).not.toContain('"pw"');
    expect(out.text).toContain('"user":"rudra"');
    expect(out.text).toContain('"ok":1');
  });
  it("redacts form-urlencoded passwords and leaves other fields", () => {
    const out = redactor.redactHttpMessage("POST /login HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n" + "q=shoes&password=hunter2&next=/home");
    expect(out.text).not.toContain("hunter2");
    expect(out.text).toContain("q=shoes");
  });
  it("withholds binary bodies entirely and never corrupts the checksum", () => {
    const raw = "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\n\r\n\x89PNG\r\n\x1a\nbinary";
    const out = redactor.redactHttpMessage(raw);
    expect(out.text).toContain("withheld");
    expect(out.checksum).toBe(sha256Hex(raw));
  });
  it("supports operator-configured sensitive headers (§28)", () => {
    const custom = new HttpEvidenceRedactor({ sensitiveHeaders: ["x-tenant-key"] });
    const out = custom.redactHttpMessage("GET / HTTP/1.1\r\nX-Tenant-Key: secret-tenant\r\n\r\n", "text/plain");
    expect(out.text).not.toContain("secret-tenant");
  });
});

describe("import security (§61/§62)", () => {
  it("rejects DOCTYPE and ENTITY declarations (XXE) but allows CDATA", () => {
    expect(() => assertXmlSafe('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>')).toThrow(ImportValidationError);
    expect(() => assertXmlSafe("<issues><issue><name><![CDATA[CSP]]></name></issue></issues>")).not.toThrow();
  });
  it("parses XML into a tree with depth limits enforced by the reader", () => {
    const doc = parseXmlDocument("<issues><issue><name>A</name></issue><issue><name>B</name></issue></issues>");
    expect(doc.name).toBe("issues");
    expect(xmlChildren(doc, "issue")).toHaveLength(2);
    const deep = "<a>".repeat(40) + "x" + "</a>".repeat(40);
    expect(() => parseXmlDocument(deep)).toThrow(/nesting/);
  });
  it("enforces the size cap and rejects non-object JSON", () => {
    expect(() => assertImportSize("x".repeat(MAX_IMPORT_BYTES + 1))).toThrow(/exceeds the/);
    expect(parseImportJson('{"a":1}')).toEqual({ a: 1 });
    expect(() => parseImportJson("{not json")).toThrow(ImportValidationError);
  });
});

describe("per-product severity & confidence mapping (§34/§35)", () => {
  it("maps each product by its own table — never assumed equal", () => {
    expect(mapZapSeverity("3")).toBe("HIGH");
    expect(mapZapSeverity("0")).toBe("INFORMATIONAL");
    expect(mapBurpSeverity("High")).toBe("HIGH");
    expect(mapBurpSeverity("Information")).toBe("INFORMATIONAL");
    expect(mapCaidoSeverity("critical")).toBe("CRITICAL");
    expect(mapCaidoSeverity("info")).toBe("INFORMATIONAL");
  });
  it("scanner-reported 'confirmed' is a confidence label, not verification", () => {
    const zap = mapZapConfidence("4");
    expect(zap.score).toBe(0.9);
    expect(zap.label).toContain("scanner-reported");
    expect(mapBurpConfidence("Certain").score).toBe(0.9);
    expect(mapBurpConfidence("Tentative").band).toBe("LOW");
  });
});

describe("proxy budget & rate limits (§44/§45)", () => {
  it("clamps workspace budgets to administrator hard caps", () => {
    const clamped = clampProxyBudget({ maxProxyRequests: 10_000_000, maxEvidenceBytes: 10 ** 12 });
    expect(clamped.maxProxyRequests).toBe(ADMIN_PROXY_CAPS.maxProxyRequests);
    expect(clamped.maxEvidenceBytes).toBe(ADMIN_PROXY_CAPS.maxEvidenceBytes);
    expect(DEFAULT_PROXY_BUDGET.maxActiveScanRequests).toBe(0); // active budget is ZERO by default
  });
  it("honours an explicit zero for active-scan requests", () => {
    expect(clampProxyBudget({ maxActiveScanRequests: 0 }).maxActiveScanRequests).toBe(0);
    expect(clampProxyBudget({ maxActiveScanRequests: 500 }).maxActiveScanRequests).toBe(500);
  });
  it("clamps connector rate limits to platform caps", () => {
    const rl = clampConnectorRateLimits({ requestsPerSecond: 10_000, concurrency: 999 });
    expect(rl.requestsPerSecond).toBe(50);
    expect(rl.concurrency).toBe(8);
  });
});

describe("form & traffic classification (§46–§51)", () => {
  it("classifies forms conservatively", () => {
    expect(classifyFormSafety({ action: "/search", fieldNames: ["q"] })).toBe("SAFE");
    expect(classifyFormSafety({ action: "/account/delete", fieldNames: [] })).toBe("DESTRUCTIVE");
    expect(classifyFormSafety({ action: "/profile", method: "POST", fieldNames: ["displayName"] })).toBe("UNKNOWN");
    expect(classifyFormSafety({ action: "/billing", fieldNames: ["cardNumber"] })).toBe("SENSITIVE");
  });
  it("detects logout endpoints and classifies API traffic", () => {
    expect(isLogoutUrl("https://example.com/logout")).toBe(true);
    expect(isLogoutUrl("https://example.com/account")).toBe(false);
    expect(classifyApiKind("https://example.com/graphql", "application/json")).toBe("GRAPHQL");
    expect(classifyApiKind("https://example.com/api/users", "application/json")).toBe("REST");
    expect(classifyApiKind("https://example.com/things", "application/vnd.api+json")).toBe("JSON_API");
    expect(classifyApiKind("https://example.com/about", "text/html")).toBe("WEB");
    expect(isGraphQlEndpoint("https://example.com/api/graphql")).toBe(true);
    expect(isOpenApiDocumentUrl("https://example.com/swagger.json")).toBe(true);
  });
});

const NOW = "2026-10-07T00:00:00.000Z";
function approval(overrides: Partial<ScanApprovalRecord> = {}): ScanApprovalRecord {
  return {
    id: "appr-1", workspaceId: "ws-1", scanId: "scan-1", assessmentId: "asmt-1",
    capability: "ACTIVE_WEB_SCANNING", status: "ACTIVE",
    scopeSnapshotHash: hashScopeSnapshot(SCOPE),
    approvedBy: "u-owner", approvedAt: NOW,
    expiresAt: "2026-10-08T00:00:00.000Z",
    ...overrides,
  };
}
function gateInput(overrides: Record<string, unknown> = {}) {
  return {
    targetVerified: true, scopeApproved: true, assessmentApproved: true, activeTestingEnabled: true,
    userRole: "OWNER", adminPolicyPermits: true, approval: approval(),
    currentScopeHash: hashScopeSnapshot(SCOPE), activeBudgetRequests: 100, now: new Date(NOW),
    ...overrides,
  };
}

describe("active-scan approval gate (§40–§43, §70)", () => {
  it("denies unverified targets, unapproved assessments and disabled policy first", () => {
    expect(evaluateActiveScanGate(gateInput({ targetVerified: false })).reasonCode).toBe("TARGET_NOT_VERIFIED");
    expect(evaluateActiveScanGate(gateInput({ scopeApproved: false })).reasonCode).toBe("SCOPE_NOT_APPROVED");
    expect(evaluateActiveScanGate(gateInput({ assessmentApproved: false })).reasonCode).toBe("ASSESSMENT_NOT_APPROVED");
    expect(evaluateActiveScanGate(gateInput({ activeTestingEnabled: false })).reasonCode).toBe("ACTIVE_TESTING_NOT_ENABLED");
    expect(evaluateActiveScanGate(gateInput({ userRole: "ANALYST" })).reasonCode).toBe("ROLE_NOT_PERMITTED");
    expect(evaluateActiveScanGate(gateInput({ adminPolicyPermits: false })).reasonCode).toBe("ADMIN_POLICY_DENIES");
  });
  it("denies missing, expired, revoked and scope-invalidated approvals", () => {
    expect(evaluateActiveScanGate(gateInput({ approval: null })).reasonCode).toBe("APPROVAL_MISSING");
    expect(evaluateActiveScanGate(gateInput({ approval: approval({ expiresAt: "2026-10-06T00:00:00.000Z" }) })).reasonCode).toBe("APPROVAL_EXPIRED");
    expect(evaluateActiveScanGate(gateInput({ approval: approval({ status: "REVOKED", revokedAt: NOW }) })).reasonCode).toBe("APPROVAL_REVOKED");
    const changedHash = hashScopeSnapshot({ ...SCOPE, includeHosts: ["example.com", "other.example.com"] });
    expect(evaluateActiveScanGate(gateInput({ currentScopeHash: changedHash })).reasonCode).toBe("APPROVAL_INVALIDATED_SCOPE_CHANGED");
    const state = evaluateApproval(approval(), { capability: "ACTIVE_WEB_SCANNING", currentScopeHash: hashScopeSnapshot(SCOPE), now: new Date(NOW) });
    expect(state.state).toBe("VALID");
    expect(state.usable).toBe(true);
  });
  it("denies when the active budget is zero, and allows only when every gate passes", () => {
    expect(evaluateActiveScanGate(gateInput({ activeBudgetRequests: 0 })).reasonCode).toBe("NO_ACTIVE_BUDGET");
    const allowed = evaluateActiveScanGate(gateInput());
    expect(allowed.allowed).toBe(true);
    expect(allowed.reasonCode).toBe("APPROVED");
  });
});
