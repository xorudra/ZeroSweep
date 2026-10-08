import { describe, expect, it } from "vitest";
import {
  ANALYTICS_EVENT_TYPES, analyticsEventChecksum, validateAnalyticsEvent, type AnalyticsEventInput,
} from "./events";
import {
  DSL_LIMITS, describeDsl, evaluateDsl, matchedFields, parseSecurityQueryDsl, type DslRecord,
} from "./dsl";
import { bucketForRange, distribution, groupCount, percentile, timeSeries, topN, trend } from "./aggregate";
import { mttrBy, projectFindingLifecycle, regressionRanking, slaBuckets, type LifecycleProjection } from "./lifecycle";
import { buildSearchableText, computeFacets, escapeSnippetHtml, makeSnippet, matchesTokens, suggestValues } from "./search";
import { BUILTIN_CORRELATION_RULES, evaluateCorrelation, type CorrelationSubject } from "./correlation";
import { scoreAttackPath, traverseGraph, type AnalyticsGraphEdge, type AnalyticsGraphNode } from "./graph";
import { explainAttackPath, explainTrend, translateNlToDsl } from "./ai";
import { analyticsCacheKey, isExpired, retentionCutoff } from "./retention";

const BASE_EVENT: AnalyticsEventInput = {
  eventId: "evt-1", organizationId: "org-1", workspaceId: "ws-1",
  eventType: "FINDING_CREATED", eventTime: "2026-10-01T00:00:00.000Z",
  sourceType: "FIXTURE", resourceType: "FINDING", resourceId: "f-1", findingId: "f-1",
  severity: "HIGH", riskScore: 72, attributes: { cwe: "CWE-89" },
};

describe("analytics events (§4/§6/§12)", () => {
  it("accepts a valid canonical event and checksums deterministically", () => {
    expect(validateAnalyticsEvent(BASE_EVENT, new Date("2026-10-02T00:00:00Z"))).toEqual([]);
    expect(analyticsEventChecksum(BASE_EVENT)).toBe(analyticsEventChecksum({ ...BASE_EVENT }));
    expect(analyticsEventChecksum(BASE_EVENT)).not.toBe(analyticsEventChecksum({ ...BASE_EVENT, riskScore: 10 }));
  });
  it("rejects unknown types, missing tenant context and future timestamps", () => {
    const now = new Date("2026-10-02T00:00:00Z");
    expect(validateAnalyticsEvent({ ...BASE_EVENT, eventType: "WHATEVER" }, now)).toContain("EVENT_TYPE_UNKNOWN");
    expect(validateAnalyticsEvent({ ...BASE_EVENT, workspaceId: "" }, now)).toContain("WORKSPACE_MISSING");
    expect(validateAnalyticsEvent({ ...BASE_EVENT, eventTime: "2030-01-01T00:00:00Z" }, now)).toContain("EVENT_TIME_IN_FUTURE");
    expect(validateAnalyticsEvent({ ...BASE_EVENT, severity: "SEVERE" }, now)).toContain("SEVERITY_UNKNOWN");
    expect(ANALYTICS_EVENT_TYPES).toContain("FINDING_REGRESSED");
  });
  it("rejects oversized attribute payloads (§13)", () => {
    const big = { blob: "x".repeat(9000) };
    expect(validateAnalyticsEvent({ ...BASE_EVENT, attributes: big }, new Date("2026-10-02T00:00:00Z"))).toContain("ATTRIBUTES_TOO_LARGE");
  });
});

describe("SecurityQueryDSL (§34–§38, §125, §126)", () => {
  it("parses field filters, ranges, boolean and NOT/OR groups into a typed AST", () => {
    const r = parseSecurityQueryDsl("severity:critical kev:true internet_exposed:true technology:wordpress risk:>=80 NOT status:resolved");
    expect("ast" in r).toBe(true);
    if ("ast" in r) {
      expect(r.ast.kind).toBe("AND");
      expect(describeDsl(r.ast)).toContain("severity = critical");
    }
    const or = parseSecurityQueryDsl("(severity:critical OR severity:high) cwe:cwe-89");
    expect("ast" in or).toBe(true);
  });
  it("evaluates the AST against records — never as SQL", () => {
    const parsed = parseSecurityQueryDsl("severity:critical kev:true risk:>=80");
    if (!("ast" in parsed)) throw new Error("parse failed");
    const rec: DslRecord = { severity: "critical", kev: true, risk: 91, _text: "critical kev finding" };
    expect(evaluateDsl(parsed.ast, rec)).toBe(true);
    expect(evaluateDsl(parsed.ast, { ...rec, risk: 40 })).toBe(false);
    expect(matchedFields(parsed.ast, rec).length).toBe(3);
  });
  it("§125: SQL/Lucene/HTML-shaped input is inert data, not execution", () => {
    const r = parseSecurityQueryDsl("' OR '1'='1 -- <script>alert(1)</script>");
    // It parses only as plain terms (data) or is rejected — it can never become SQL.
    if ("ast" in r) {
      const rec: DslRecord = { _text: "an ordinary finding title" };
      expect(evaluateDsl(r.ast, rec)).toBe(false);
    } else {
      expect(r.rejected).toBeTruthy();
    }
  });
  it("§126: complexity limits reject pathological queries", () => {
    const nested = "((((((((((severity:critical))))))))))";
    const r = parseSecurityQueryDsl(nested);
    expect("rejected" in r).toBe(true);
    const many = Array.from({ length: DSL_LIMITS.maxClauses + 5 }, (_, i) => `technology:t${i}`).join(" ");
    expect("rejected" in parseSecurityQueryDsl(many)).toBe(true);
    expect("rejected" in parseSecurityQueryDsl("x".repeat(DSL_LIMITS.maxQueryLength + 1))).toBe(true);
    expect("rejected" in parseSecurityQueryDsl("bogus_field:1")).toBe(true);
    expect("rejected" in parseSecurityQueryDsl("risk:>=notanumber")).toBe(true);
  });
  it("supports date sugar and IN lists", () => {
    const r = parseSecurityQueryDsl("severity:critical,high after:2026-09-01");
    if (!("ast" in r)) throw new Error("parse failed");
    expect(evaluateDsl(r.ast, { severity: "high", _time: "2026-10-01T00:00:00Z" })).toBe(true);
    expect(evaluateDsl(r.ast, { severity: "high", _time: "2026-01-01T00:00:00Z" })).toBe(false);
  });
});

describe("aggregations (§39–§40)", () => {
  const rows = [
    { t: "2026-10-01T10:00:00Z", sev: "HIGH" }, { t: "2026-10-01T12:00:00Z", sev: "HIGH" },
    { t: "2026-10-03T09:00:00Z", sev: "LOW" },
  ];
  it("time series counts only real records; range zeros are real zeros", () => {
    const s = timeSeries(rows, (r) => r.t, "day", { from: new Date("2026-10-01T00:00:00Z"), to: new Date("2026-10-03T00:00:00Z") });
    expect(s.map((p) => p.count)).toEqual([2, 0, 1]);
    expect(timeSeries([], (r: { t: string }) => r.t, "day")).toEqual([]);
    expect(bucketForRange(new Date("2026-10-01"), new Date("2026-10-02"))).toBe("hour");
  });
  it("group/topN/distribution/percentile are exact and honest on empty input", () => {
    expect(groupCount(rows, (r) => r.sev)).toEqual([{ key: "HIGH", count: 2 }, { key: "LOW", count: 1 }]);
    expect(topN(rows, (r) => r.sev, 1)).toEqual([{ key: "HIGH", count: 2 }]);
    expect(distribution(rows, (r) => r.sev)[0]?.share).toBeCloseTo(2 / 3);
    expect(percentile([10, 20, 30, 40], 50)).toBe(20);
    expect(percentile([], 95)).toBeNull();
    expect(trend(10, 0).deltaPct).toBeNull(); // never an invented percentage
    expect(trend(15, 10)).toEqual({ current: 15, previous: 10, delta: 5, deltaPct: 0.5 });
  });
});

function evt(partial: Partial<AnalyticsEventInput>): AnalyticsEventInput {
  return { ...BASE_EVENT, ...partial };
}

describe("finding lifecycle projection (§43–§49, §132–§134)", () => {
  const events: AnalyticsEventInput[] = [
    evt({ eventId: "e3", eventType: "FINDING_RESOLVED", eventTime: "2026-10-05T00:00:00.000Z" }),
    evt({ eventId: "e1", eventType: "FINDING_CREATED", eventTime: "2026-10-01T00:00:00.000Z" }),
    evt({ eventId: "e2", eventType: "FINDING_VERIFIED", eventTime: "2026-10-02T00:00:00.000Z" }),
    evt({ eventId: "e4", eventType: "FINDING_REOPENED", eventTime: "2026-10-07T00:00:00.000Z" }),
    evt({ eventId: "e5", eventType: "FINDING_RESOLVED", eventTime: "2026-10-09T00:00:00.000Z" }),
  ];
  it("§132/§134: out-of-order arrival still yields the correct timeline + MTTR + regression", () => {
    const p = projectFindingLifecycle(events);
    expect(p).not.toBeNull();
    expect(p!.firstSeenAt).toBe("2026-10-01T00:00:00.000Z");
    expect(p!.verifiedAt).toBe("2026-10-02T00:00:00.000Z");
    expect(p!.resolvedAt).toBe("2026-10-05T00:00:00.000Z");
    expect(p!.regressionCount).toBe(1);
    expect(p!.remediationSeconds).toBe(4 * 86_400);
    expect(p!.currentStatus).toBe("RESOLVED");
    // §133: replay determinism — shuffled input, same projection.
    const shuffled = [events[3]!, events[0]!, events[4]!, events[1]!, events[2]!];
    const p2 = projectFindingLifecycle(shuffled);
    expect(p2!.remediationSeconds).toBe(p!.remediationSeconds);
    expect(p2!.regressionCount).toBe(p!.regressionCount);
  });
  it("MTTR groups honestly: unresolved findings never enter the mean", () => {
    const resolved: LifecycleProjection = {
      findingId: "a", firstSeenAt: "2026-10-01T00:00:00Z", lastSeenAt: "2026-10-03T00:00:00Z",
      triagedAt: null, verifiedAt: null, resolvedAt: "2026-10-03T00:00:00Z", reopenedAt: null,
      regressionCount: 0, remediationSeconds: 172_800, currentStatus: "RESOLVED",
      severity: "HIGH", cwe: "CWE-89", cve: null, assetId: "as-1", repositoryId: null,
    };
    const open: LifecycleProjection = { ...resolved, findingId: "b", resolvedAt: null, remediationSeconds: null, currentStatus: "OPEN" };
    const groups = mttrBy([resolved, open], (p) => p.severity);
    expect(groups).toEqual([{ key: "HIGH", resolvedCount: 1, unresolvedCount: 1, meanSeconds: 172_800, medianSeconds: 172_800 }]);
    expect(regressionRanking([resolved, open])).toEqual([]);
  });
  it("SLA buckets separate within/approaching/overdue/breached/met/no-deadline", () => {
    const now = new Date("2026-10-10T00:00:00Z");
    const b = slaBuckets([
      { dueAt: "2026-12-01T00:00:00Z", resolvedAt: null, status: "OPEN" },
      { dueAt: "2026-10-11T00:00:00Z", resolvedAt: null, status: "OPEN" },
      { dueAt: "2026-10-09T00:00:00Z", resolvedAt: null, status: "OPEN" },
      { dueAt: "2026-10-01T00:00:00Z", resolvedAt: "2026-09-30T00:00:00Z", status: "RESOLVED" },
      { dueAt: null, resolvedAt: null, status: "OPEN" },
    ], now, { approachingHours: 72, graceHours: 48 });
    expect(b).toEqual({ WITHIN: 1, APPROACHING: 1, OVERDUE: 1, BREACHED: 0, MET: 1, NO_DEADLINE: 1 });
  });
});

describe("search safety (§25/§30/§31/§129/§130)", () => {
  it("§130: a synthetic secret in source text is absent from the index text", () => {
    const text = buildSearchableText(["Leaked key AKIAIOSFODNN7EXAMPLE in evidence", "normal title"]);
    expect(text).not.toContain("AKIAIOSFODNN7EXAMPLE");
    expect(text).toContain("normal title");
  });
  it("§129: snippets escape HTML/script from indexed titles", () => {
    const snippet = makeSnippet(`<script>alert("x")</script> critical finding`, ["critical"]);
    expect(snippet).not.toContain("<script>");
    expect(snippet).toContain("&lt;script&gt;");
    expect(escapeSnippetHtml(`a & "b"`)).toBe("a &amp; &quot;b&quot;");
  });
  it("token match + facets + suggestions over scoped values only", () => {
    expect(matchesTokens("critical wordpress finding", ["critical", "wordpress"])).toBe(true);
    expect(matchesTokens("critical wordpress finding", ["critical", "nginx"])).toBe(false);
    const facets = computeFacets([{ s: "HIGH" }, { s: "HIGH" }, { s: "LOW" }], (d) => ({ severity: d.s }));
    expect(facets.severity).toEqual([{ value: "HIGH", count: 2 }, { value: "LOW", count: 1 }]);
    expect(suggestValues(["wordpress", "nginx", "wordfence"], "word")).toEqual(["wordpress", "wordfence"]);
  });
});

describe("correlation (§73–§80, §136, §137)", () => {
  it("§136: KEV + internet-exposed finding produces INTERNET_EXPOSED_KEV", () => {
    const subject: CorrelationSubject = { findingId: "f-1", assetId: "a-1", kevListed: true, internetExposed: true, verificationStatus: "CONFIRMED", cve: "CVE-2021-44228" };
    const matches = evaluateCorrelation(subject, "ws-1");
    expect(matches.map((m) => m.rule.outputType)).toContain("INTERNET_EXPOSED_KEV");
    const m = matches.find((x) => x.rule.outputType === "INTERNET_EXPOSED_KEV")!;
    expect(m.fingerprint).toHaveLength(64);
    expect(m.evidence.cve).toBe("CVE-2021-44228");
  });
  it("§137: critical asset + verified critical finding = high-confidence signal", () => {
    const subject: CorrelationSubject = { findingId: "f-2", assetId: "a-2", assetCriticality: "CRITICAL", findingSeverity: "CRITICAL", verificationStatus: "CONFIRMED", internetExposed: false };
    const matches = evaluateCorrelation(subject, "ws-1");
    const m = matches.find((x) => x.rule.outputType === "CRITICAL_ASSET_CRITICAL_FINDING");
    expect(m).toBeDefined();
    expect(m!.confidence).toBe("HIGH");
  });
  it("no match when conditions are not met; rules are data (no code)", () => {
    expect(evaluateCorrelation({ kevListed: false, internetExposed: true }, "ws-1")).toEqual([]);
    expect(BUILTIN_CORRELATION_RULES.length).toBeGreaterThanOrEqual(6);
  });
});

describe("graph + attack paths (§81–§87, §138, §139)", () => {
  const nodes: AnalyticsGraphNode[] = [
    { id: "internet", kind: "INTERNET", label: "Internet" },
    { id: "web", kind: "ASSET", label: "web-1" },
    { id: "db", kind: "ASSET", label: "db-1" },
  ];
  const edges: AnalyticsGraphEdge[] = [
    { from: "internet", to: "web", relation: "EXPOSES", evidenceType: "ASSET_EXPOSURE", evidenceId: "web" },
    { from: "web", to: "db", relation: "CONNECTS", evidenceType: "ASSET_RELATIONSHIP", evidenceId: "rel-1" },
  ];
  it("traverses within limits and rejects excessive depth (§139)", () => {
    const r = traverseGraph(nodes, edges, "internet", { maxDepth: 2 });
    expect("nodes" in r && r.nodes.length).toBe(3);
    const bad = traverseGraph(nodes, edges, "internet", { maxDepth: 99 });
    expect("rejected" in bad).toBe(true);
  });
  it("§138: scores an evidence-backed container/web path candidate deterministically", () => {
    const scored = scoreAttackPath({
      entry: { assetId: "web", label: "web-1", criticality: "HIGH" },
      finding: { id: "f-9", title: "Critical RCE in web-1", severity: "CRITICAL", riskScore: 92, verificationStatus: "CONFIRMED", cve: "CVE-2021-44228" },
      downstream: { assetId: "db", label: "db-1", criticality: "CRITICAL", dataSensitivity: "RESTRICTED", relationEvidenceId: "rel-1" },
    });
    expect(scored.score).toBeGreaterThan(70);
    expect(scored.confidence).toBe("HIGH");
    expect(scored.edges.every((e) => e.evidenceId)).toBe(true);
    expect(scored.fingerprint).toHaveLength(64);
    const again = scoreAttackPath({
      entry: { assetId: "web", label: "web-1", criticality: "HIGH" },
      finding: { id: "f-9", title: "Critical RCE in web-1", severity: "CRITICAL", riskScore: 92, verificationStatus: "CONFIRMED", cve: "CVE-2021-44228" },
      downstream: { assetId: "db", label: "db-1", criticality: "CRITICAL", dataSensitivity: "RESTRICTED", relationEvidenceId: "rel-1" },
    });
    expect(again.score).toBe(scored.score);
    expect(explainAttackPath(scored)).toContain("not an exploitation procedure");
  });
});

describe("AI analytics grounding (§104–§109, §140, §141)", () => {
  it("translates natural language into the governed DSL — never SQL", () => {
    const r = translateNlToDsl("critical public WordPress findings");
    expect("dsl" in r && r.dsl).toContain("internet_exposed:true");
    expect("dsl" in r && r.dsl).toContain("technology:wordpress");
    expect("rejected" in translateNlToDsl("x'; DROP TABLE findings; --")).toBe(true);
    expect("rejected" in translateNlToDsl("tell me a story")).toBe(true);
  });
  it("§140: trend explanation cites only supplied deterministic numbers", () => {
    const ok = explainTrend({ metric: "Critical exposure", seriesPoints: 8, current: 14, previous: 9, rangeLabel: "this week vs last week" });
    expect(ok.status).toBe("OK");
    expect(ok.text).toContain("from 9 to 14");
  });
  it("§141: insufficient history yields INSUFFICIENT_DATA, not an invented trend", () => {
    const out = explainTrend({ metric: "Risk", seriesPoints: 1, current: 5, previous: null, rangeLabel: "this week" });
    expect(out.status).toBe("INSUFFICIENT_DATA");
    expect(out.text).toContain("INSUFFICIENT_DATA");
  });
});

describe("retention + cache keys (§113/§122–§124/§142)", () => {
  const policy = { eventRetentionDays: 730, searchDocRetentionDays: 730, snapshotRetentionDays: 365, restrictedEventRetentionDays: 365 };
  it("cutoffs differ by kind and restricted classification; audit kinds are not lake records", () => {
    const now = new Date("2026-10-08T00:00:00Z");
    expect(retentionCutoff(policy, "SNAPSHOT", null, now).toISOString()).toBe("2025-10-08T00:00:00.000Z");
    expect(isExpired(policy, "ANALYTICS_EVENT", "RESTRICTED", new Date("2024-01-01"), now)).toBe(true);
    expect(isExpired(policy, "ANALYTICS_EVENT", "INTERNAL", new Date("2026-01-01"), now)).toBe(false);
  });
  it("§142: cache keys differ across tenants and security contexts", () => {
    const base = { organizationId: "org-1", workspaceId: "ws-1", role: "ANALYST", permissions: ["VIEW_ANALYTICS"], classificationCeiling: "INTERNAL", view: "OVERVIEW", filters: {} };
    const a = analyticsCacheKey(base);
    expect(analyticsCacheKey({ ...base, workspaceId: "ws-2" })).not.toBe(a);
    expect(analyticsCacheKey({ ...base, organizationId: "org-2" })).not.toBe(a);
    expect(analyticsCacheKey({ ...base, classificationCeiling: "RESTRICTED" })).not.toBe(a);
    expect(analyticsCacheKey({ ...base, permissions: ["VIEW_ANALYTICS", "EXPORT"] })).not.toBe(a);
    expect(analyticsCacheKey(base)).toBe(a);
  });
});
