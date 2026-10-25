import { FixtureScannerTransport, type FixtureRoute } from "./connector";
import type { ScannerInstanceRecord } from "./types";

/**
 * Recorded proxy/scanner fixtures (Prompt 8 §64–§68). These are captured
 * response SHAPES for a controlled local test application on example.com —
 * no live scanner, target or network is involved. Traffic fixtures embed
 * OBVIOUSLY FAKE credentials ("fixture-…") on purpose: the redaction
 * tests prove none of them survive into normalized output.
 */

export const ZAP_VERSION = { version: "2.15.0" };

export const ZAP_ALERTS = {
  alerts: [
    {
      pluginId: "10038", alert: "Content Security Policy (CSP) Header Not Set", name: "Content Security Policy (CSP) Header Not Set",
      riskcode: "1", confidence: "2", riskdesc: "Low (Medium)",
      desc: "<p>Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks.</p>",
      instances: [{ uri: "https://example.com/", method: "GET", param: "", attack: "", evidence: "" }],
      count: "1", solution: "<p>Ensure that your web server, application server, load balancer, etc. is configured to set the Content-Security-Policy header.</p>",
      reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
      cweid: "693", wascid: "15", sourceid: "3",
    },
    {
      pluginId: "10054", alert: "Cookie Without SameSite Attribute", name: "Cookie Without SameSite Attribute",
      riskcode: "1", confidence: "2", riskdesc: "Low (Medium)",
      desc: "<p>A cookie has been set without the SameSite attribute.</p>",
      instances: [{ uri: "https://example.com/login", method: "GET", param: "", attack: "", evidence: "Set-Cookie: session" }],
      count: "1", solution: "<p>Set the SameSite attribute on cookies.</p>",
      reference: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie",
      cweid: "1275", wascid: "13", sourceid: "3",
    },
    {
      pluginId: "10109", alert: "Modern Web Application", name: "Modern Web Application",
      riskcode: "0", confidence: "2", riskdesc: "Informational (Medium)",
      desc: "<p>The application appears to be a modern web application.</p>",
      instances: [{ uri: "https://example.com/", method: "GET", param: "", attack: "", evidence: "" }],
      count: "1", solution: "", reference: "", cweid: "", wascid: "", sourceid: "3",
    },
  ],
};

export const ZAP_URLS = [
  { url: "https://example.com/" },
  { url: "https://example.com/login" },
  { url: "https://example.com/search?q=shoes&page=2" },
  { url: "https://example.com/account" },
  { url: "https://thirdparty.example.net/tracker" },
];

export const ZAP_MESSAGES = [
  {
    id: "1",
    requestHeader: "GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\nUser-Agent: fixture\r\nCookie: session=fixture-zap-secret\r\n\r\n",
    requestBody: "",
    responseHeader: "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nSet-Cookie: session=fixture-zap-secret; Path=/\r\n\r\n",
    responseBody: "<html><title>Example</title></html>",
  },
  {
    id: "2",
    requestHeader: "GET https://example.com/account HTTP/1.1\r\nHost: example.com\r\nCookie: session=fixture-zap-secret\r\nAuthorization: Bearer fixture-zap-token\r\n\r\n",
    requestBody: "",
    responseHeader: "HTTP/1.1 302 Found\r\nLocation: https://example.com/login\r\n\r\n",
    responseBody: "",
  },
];

export const BURP_ISSUES_XML = `<?xml version="1.0" encoding="UTF-8"?>
<issues burpVersion="2024.1" exportTime="2026-10-07T00:00:00Z">
  <issue>
    <serialNumber>1001</serialNumber>
    <type>134217728</type>
    <name><![CDATA[Content Security Policy (CSP) Header Not Set]]></name>
    <host ip="93.184.216.34">https://example.com</host>
    <path><![CDATA[/]]></path>
    <location><![CDATA[/]]></location>
    <severity>Low</severity>
    <confidence>Firm</confidence>
    <issueBackground><![CDATA[<p>The application does not set a Content Security Policy.</p>]]></issueBackground>
    <issueDetail><![CDATA[<p>The response for / did not include a Content-Security-Policy header.</p>]]></issueDetail>
    <remediationBackground><![CDATA[<p>Set a Content-Security-Policy appropriate to the application.</p>]]></remediationBackground>
    <requestresponse>
      <request method="GET" base64="true">R0VUIC9IVFRQLzEuMQ0KSG9zdDogZXhhbXBsZS5jb20NCkNvb2tpZTogc2Vzc2lvbj1maXh0dXJlLWJ1cnAtc2VjcmV0DQpBdXRob3JpemF0aW9uOiBCZWFyZXIgZml4dXJlLWJ1cnAtdG9rZW4NCg0K</request>
      <response base64="true">SFRUUC8xLjEgMjAwIE9LDQpDb250ZW50LVR5cGU6IHRleHQvaHRtbA0KDQo8aHRtbD5leGFtcGxlPC9odG1sPg==</response>
    </requestresponse>
  </issue>
  <issue>
    <serialNumber>1002</serialNumber>
    <type>268435456</type>
    <name><![CDATA[Cross-site scripting (reflected)]]></name>
    <host ip="93.184.216.34">https://example.com</host>
    <path><![CDATA[/search?q=shoes]]></path>
    <location><![CDATA[/search]]></location>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <issueBackground><![CDATA[<p>Reflected XSS allows attacker script execution in a victim browser.</p>]]></issueBackground>
    <issueDetail><![CDATA[<p>The q parameter reflects unencoded input in the response.</p>]]></issueDetail>
    <remediationDetail><![CDATA[<p>Apply context-appropriate output encoding.</p>]]></remediationDetail>
  </issue>
</issues>`;

export const BURP_SITE_MAP = [
  { url: "https://example.com/", method: "GET", statusCode: 200 },
  { url: "https://example.com/login", method: "GET", statusCode: 200 },
  { url: "https://example.com/admin", method: "GET", statusCode: 302 },
];

export const CAIDO_EXPORT = {
  data: {
    findings: [
      { id: "f-1", title: "Content Security Policy (CSP) Header Not Set", severity: "low", url: "https://example.com/", description: "The response does not include a Content-Security-Policy header." },
    ],
    requests: [
      {
        method: "GET", url: "https://example.com/api/users", status: 200,
        request: "GET /api/users HTTP/1.1\r\nHost: example.com\r\nX-API-Key: fixture-caido-secret\r\n\r\n",
        response: "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"users\":[{\"name\":\"Rudra\"}],\"access_token\":\"fixture-caido-token\"}",
        createdAt: "2026-10-07T00:00:00Z",
      },
      { method: "GET", url: "wss://example.com/socket", isWebSocket: true },
    ],
  },
};

export const HAR_EXPORT = {
  log: {
    version: "1.2",
    creator: { name: "fixture", version: "1.0" },
    entries: [
      {
        startedDateTime: "2026-10-07T00:00:00Z", time: 42,
        request: { method: "POST", url: "https://example.com/graphql", headers: [{ name: "Content-Type", value: "application/json" }, { name: "Cookie", value: "session=fixture-har-secret" }], postData: { mimeType: "application/json", text: "{\"query\":\"{ __typename }\",\"password\":\"fixture-har-password\"}" } },
        response: { status: 200, headers: [{ name: "Content-Type", value: "application/json" }], content: { mimeType: "application/json", text: "{\"data\":{\"__typename\":\"Query\"}}" } },
      },
      {
        startedDateTime: "2026-10-07T00:00:01Z", time: 10,
        request: { method: "GET", url: "https://example.com/openapi.json", headers: [] },
        response: { status: 200, headers: [{ name: "Content-Type", value: "application/json" }], content: { mimeType: "application/json", text: "{\"openapi\":\"3.0.0\"}" } },
      },
    ],
  },
};

export const FIXTURE_INSTANCES: ScannerInstanceRecord[] = [
  {
    id: "inst-zap-1", organizationId: "org-1", toolSlug: "owasp-zap", product: "ZAP",
    name: "ZAP daemon (fixture)", endpointReference: "ZAP_DAEMON_FIXTURE", deploymentType: "MANAGED_DAEMON",
    declaredCapabilities: ["PROXY", "PASSIVE_ANALYSIS", "CONTEXT_MANAGEMENT", "ENDPOINT_IMPORT", "ISSUE_IMPORT", "WEB_CRAWLING"],
    credentialReference: "ZAP_API_KEY_FIXTURE", enabled: true, healthStatus: "HEALTHY",
    detectedCapabilities: [], createdBy: "u-1", createdAt: "2026-10-07T00:00:00Z", updatedAt: "2026-10-07T00:00:00Z",
  },
  {
    id: "inst-burp-1", organizationId: "org-1", toolSlug: "burp-suite-professional", product: "BURP",
    name: "Burp Professional (fixture)", endpointReference: "BURP_BRIDGE_FIXTURE", deploymentType: "ADMIN_PROVIDED",
    declaredCapabilities: ["PROXY", "PASSIVE_ANALYSIS", "SITE_MAP_IMPORT", "ISSUE_IMPORT"],
    credentialReference: "BURP_API_KEY_FIXTURE", enabled: true, healthStatus: "HEALTHY",
    detectedCapabilities: [], createdBy: "u-1", createdAt: "2026-10-07T00:00:00Z", updatedAt: "2026-10-07T00:00:00Z",
  },
  {
    id: "inst-caido-1", organizationId: "org-1", toolSlug: "caido", product: "CAIDO",
    name: "Caido (fixture)", endpointReference: "CAIDO_FIXTURE", deploymentType: "ADMIN_PROVIDED",
    declaredCapabilities: ["PROXY", "TRAFFIC_ANALYSIS", "ENDPOINT_DISCOVERY", "REQUEST_COLLECTION", "ISSUE_IMPORT"],
    enabled: true, healthStatus: "HEALTHY",
    detectedCapabilities: [], createdBy: "u-1", createdAt: "2026-10-07T00:00:00Z", updatedAt: "2026-10-07T00:00:00Z",
  },
];

export const FIXTURE_ENDPOINTS: Record<string, { baseUrl: string }> = {
  ZAP_DAEMON_FIXTURE: { baseUrl: "https://zap.fixture.invalid:8443" },
  BURP_BRIDGE_FIXTURE: { baseUrl: "https://burp.fixture.invalid:9443" },
  CAIDO_FIXTURE: { baseUrl: "https://caido.fixture.invalid:8443" },
};

export const FIXTURE_SECRETS: Record<string, string> = {
  ZAP_API_KEY_FIXTURE: "fixture-zap-api-key",
  BURP_API_KEY_FIXTURE: "fixture-burp-api-key",
};

/** Fixture transport routes for all three products' recorded APIs. */
export function proxyFixtureRoutes(overrides: FixtureRoute[] = []): FixtureRoute[] {
  return [
    ...overrides,
    // ZAP API (documented /JSON/... surface)
    { method: "GET", match: "/JSON/core/view/version/", respond: () => ({ body: ZAP_VERSION }) },
    { method: "GET", match: "/JSON/context/action/newContext/", respond: () => ({ body: { Result: "OK" } }) },
    { method: "GET", match: "/JSON/context/action/includeInContext/", respond: () => ({ body: { Result: "OK" } }) },
    { method: "GET", match: "/JSON/context/action/excludeFromContext/", respond: () => ({ body: { Result: "OK" } }) },
    { method: "GET", match: "/JSON/context/action/removeContext/", respond: () => ({ body: { Result: "OK" } }) },
    { method: "GET", match: "/JSON/spider/action/scan/", respond: () => ({ body: { scan: "0" } }) },
    { method: "GET", match: "/JSON/spider/view/status/", respond: () => ({ body: { status: "100" } }) },
    { method: "GET", match: "/JSON/pscan/view/recordsToScan/", respond: () => ({ body: { recordsToScan: "0" } }) },
    { method: "GET", match: "/JSON/core/view/alerts/", respond: () => ({ body: ZAP_ALERTS }) },
    { method: "GET", match: "/JSON/core/view/urls/", respond: () => ({ body: ZAP_URLS }) },
    {
      method: "GET", match: "/JSON/core/view/message/", respond: (req) => {
        const id = req.query?.id ?? "1";
        const msg = ZAP_MESSAGES.find((x) => x.id === id) ?? ZAP_MESSAGES[0]!;
        return { body: msg };
      },
    },
    { method: "GET", match: "/JSON/core/view/messages/", respond: () => ({ body: ZAP_MESSAGES.map((x) => ({ id: x.id })) }) },
    // Burp bridge (ZeroSweep's documented admin-provided bridge contract:
    // a Montoya extension / scheduled export in the licensed environment)
    { method: "GET", match: "/zerosweep/health", respond: () => ({ body: { version: "2024.1", licenseState: "Professional — licensed (fixture)" } }) },
    { method: "GET", match: "/zerosweep/issues-export", respond: () => ({ body: BURP_ISSUES_XML }) },
    { method: "GET", match: "/zerosweep/site-map", respond: () => ({ body: BURP_SITE_MAP }) },
    // Caido GraphQL-style surface (tolerant parser — §13)
    {
      method: "POST", match: "/graphql", respond: (req) => {
        const q = req.body ?? "";
        if (q.includes("__typename")) return { body: { data: { __typename: "Query" } } };
        if (q.includes("findings")) return { body: { data: { findings: CAIDO_EXPORT.data.findings } } };
        if (q.includes("requests")) return { body: { data: { requests: CAIDO_EXPORT.data.requests } } };
        return { body: { data: {} } };
      },
    },
  ];
}

export function createFixtureTransport(overrides: FixtureRoute[] = []): FixtureScannerTransport {
  return new FixtureScannerTransport(proxyFixtureRoutes(overrides));
}
