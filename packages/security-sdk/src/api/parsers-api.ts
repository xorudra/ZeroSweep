import type { ApiFindingDraft, ParsedApi } from "./api-adapter.base";
import { parseJsonLines } from "../recon/parsers-common";
import { parseXmlDocument, xmlChild, xmlChildren, xmlText } from "../proxy/import-security";
import { redactEvidenceText } from "../vuln/redact";
import { sourceFindingFingerprint } from "../vuln/analysis";
import { parseGraphqlIntrospection } from "./importers";
import { SpecImportError } from "./import-security";
import { owaspApiCategoryFor } from "./taxonomy";

/**
 * Tool-output parsers for the API security engine (Prompt 9). Tool output
 * is UNTRUSTED: malformed records become warnings, never throws (§66
 * posture from earlier phases). Parsers never invent results — empty or
 * unparsable output parses to empty inventory, not to findings.
 */

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}
function str(v: unknown): string | undefined {
  return typeof v === "string" && v.length > 0 ? v : undefined;
}
function num(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}
function hostOf(url: string): string {
  try { return new URL(url).hostname; } catch { return url; }
}
function extractUrlFromText(text: string): string | undefined {
  const m = text.match(/https?:\/\/[^\s"'\]<]+/);
  return m ? m[0] : undefined;
}

export function emptyParsedApi(): ParsedApi {
  return { findings: [], assets: [], services: [], endpoints: [], parameters: [], apiServices: [], graphqlServices: [], jwtProfiles: [], warnings: [] };
}

/** Kiterunner JSON-lines output (§13): one object per discovered route.
 *  Field names vary slightly across versions, so parsing is tolerant. */
export function parseKiterunnerOutput(text: string, source: string, baseUrl: string): ParsedApi {
  const out = emptyParsedApi();
  const { records, warnings } = parseJsonLines(text, "kiterunner");
  out.warnings.push(...warnings);
  const base = baseUrl.replace(/\/+$/, "");
  let routes = 0;
  for (const record of records) {
    if (!isRecord(record)) continue;
    const method = (str(record.method) ?? "GET").toUpperCase();
    const target = str(record.path) ?? str(record.url) ?? str(record.target) ?? "";
    if (!target) continue;
    const full = /^https?:\/\//i.test(target) ? target : `${base}${target.startsWith("/") ? "" : "/"}${target}`;
    const url = full.split("?")[0]!;
    const status = num(record.statusCode) ?? num(record.status) ?? num(record.code);
    const headers = isRecord(record.headers) ? record.headers : undefined;
    const contentType = str(record.contentType) ?? (headers ? str(headers["content-type"]) ?? str(headers["Content-Type"]) : undefined);
    out.endpoints.push({
      url, method, source, sources: [source],
      parameterNames: [], endpointType: "API",
      ...(status !== undefined ? { statusCode: status } : {}),
      ...(contentType ? { contentType } : {}),
    });
    routes++;
  }
  out.metrics = { routes };
  return out;
}

/** Schemathesis JUnit XML report (§15): each failed testcase is one
 *  schema-conformance failure for one operation. Passing testcases
 *  produce NO findings (§62 — safe checks only, evidence-based). */
const SCHEMATHESIS_CHECK_CLASSES: Record<string, { vulnClass: string; severity: "MEDIUM" | "LOW"; title: string }> = {
  not_a_server_error: { vulnClass: "API_SERVER_ERROR", severity: "MEDIUM", title: "API Returns Server Errors for Valid Requests" },
  status_code_conformance: { vulnClass: "API_RESPONSE_CONFORMANCE", severity: "LOW", title: "API Status Code Does Not Conform to Its Schema" },
  content_type_conformance: { vulnClass: "API_RESPONSE_CONFORMANCE", severity: "LOW", title: "API Content-Type Does Not Conform to Its Schema" },
  response_schema_conformance: { vulnClass: "API_RESPONSE_CONFORMANCE", severity: "MEDIUM", title: "API Response Body Does Not Conform to Its Schema" },
  response_headers_conformance: { vulnClass: "API_RESPONSE_CONFORMANCE", severity: "LOW", title: "API Response Headers Do Not Conform to Its Schema" },
};

export function parseSchemathesisJUnit(xml: string, source: string): ParsedApi {
  const out = emptyParsedApi();
  let root;
  try {
    root = parseXmlDocument(xml);
  } catch (err) {
    out.warnings.push(`schemathesis JUnit output not parseable: ${err instanceof Error ? err.message : "unknown error"}`);
    return out;
  }
  const suites = root.name === "testsuites" ? xmlChildren(root, "testsuite") : root.name === "testsuite" ? [root] : [];
  let executed = 0;
  let failures = 0;
  for (const suite of suites) {
    for (const testcase of xmlChildren(suite, "testcase")) {
      executed++;
      const failure = xmlChild(testcase, "failure") ?? xmlChild(testcase, "error");
      if (!failure) continue; // passed — no finding
      failures++;
      const classname = testcase.attributes.classname ?? "";
      const name = testcase.attributes.name ?? "";
      const checkKey = Object.keys(SCHEMATHESIS_CHECK_CLASSES).find((k) => classname.toLowerCase().includes(k) || name.toLowerCase().includes(k));
      const mapped = checkKey ? SCHEMATHESIS_CHECK_CLASSES[checkKey]! : { vulnClass: "API_RESPONSE_CONFORMANCE", severity: "LOW" as const, title: "API Schema Conformance Check Failed" };
      const endpoint = extractUrlFromText(`${classname} ${name}`) ?? "https://api.invalid/unknown-operation";
      const message = failure.attributes.message ?? xmlText(failure);
      const owasp = owaspApiCategoryFor(mapped.vulnClass);
      const finding: ApiFindingDraft = {
        title: mapped.title,
        description: `Schemathesis safe schema-based testing reported a conformance failure for this operation (check: ${checkKey ?? "unspecified"}). Only operations the API operation policy classified as safe were exercised; state-changing operations were filtered out before execution (§15/§62).`,
        severity: mapped.severity,
        confidence: 0.85,
        host: hostOf(endpoint),
        endpoint,
        sourceTool: source,
        sourceFingerprint: sourceFindingFingerprint({ sourceTool: source, host: hostOf(endpoint), endpoint, vulnClass: mapped.vulnClass, checkId: checkKey ?? "schemathesis" }),
        references: [],
        evidence: redactEvidenceText([name || classname, message].filter(Boolean).join(" — ")).slice(0, 400),
        evidenceDetail: { checkId: checkKey ?? "schemathesis", metadata: { check: checkKey ?? "unspecified" } },
        remediation: mapped.vulnClass === "API_SERVER_ERROR"
          ? "Fix the server-side fault for this operation and ensure error responses do not leak stack traces or internals."
          : "Align the implementation with the published schema (status codes, content types, response bodies).",
        ...(mapped.vulnClass === "API_SERVER_ERROR" ? { cwe: "CWE-703" } : {}),
        ...(owasp ? { owaspCategory: owasp } : {}),
        vulnClass: mapped.vulnClass,
      };
      out.findings.push(finding);
    }
  }
  out.metrics = { executedCases: executed, failures };
  return out;
}

/** InQL output (§27): InQL dumps the introspection result (JSON) it
 *  retrieved from the target. Parsing REUSES the platform's introspection
 *  inventory parser — the tool adds reachability, not new semantics. */
export function parseInqlOutput(text: string, source: string, endpointUrl: string): ParsedApi {
  const out = emptyParsedApi();
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    out.warnings.push("inql output was not valid JSON — no GraphQL inventory extracted");
    return out;
  }
  try {
    const inventory = parseGraphqlIntrospection(doc, { endpointUrl, source });
    out.graphqlServices.push(inventory.service);
    out.warnings.push(...inventory.warnings);
    out.metrics = {
      graphqlOperations: inventory.service.queries + inventory.service.mutations + inventory.service.subscriptions,
      types: inventory.service.types,
    };
  } catch (err) {
    if (err instanceof SpecImportError) out.warnings.push(`inql output contained no introspection schema: ${err.message}`);
    else throw err;
  }
  return out;
}

/** GraphQLmap output (§28): text probing output. The parser records only
 *  DURABLE inventory facts (the endpoint responds to GraphQL; an engine
 *  name the tool itself reported). GraphQLmap's probing payloads are
 *  never replayed by the platform, and introspection being enabled is
 *  inventory, NOT a finding (§29). */
export function parseGraphqlmapOutput(text: string, source: string, endpointUrl: string): ParsedApi {
  const out = emptyParsedApi();
  const lowered = text.toLowerCase();
  if (text.trim().length === 0 || !lowered.includes("graphql")) {
    out.warnings.push("graphqlmap produced no GraphQL evidence — endpoint not confirmed as GraphQL");
    return out;
  }
  const engine = /graphql-ruby|graphql-php|graphql-java|graphql-js|apollo|hasura|graphql-yoga|absinthe/i.exec(text)?.[0];
  out.graphqlServices.push({
    endpointUrl, host: hostOf(endpointUrl), schemaAvailable: lowered.includes("introspection"),
    queries: 0, mutations: 0, subscriptions: 0, types: 0, source,
  });
  out.metrics = { graphqlEndpoints: 1 };
  if (engine) out.warnings.push(`graphqlmap fingerprinted the engine as '${engine}' (tool-reported, unverified)`);
  return out;
}
