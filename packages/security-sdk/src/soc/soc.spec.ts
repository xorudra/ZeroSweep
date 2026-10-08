import { describe, expect, it } from "vitest";
import { normalizeTelemetryEvent, telemetryFingerprint, verifyTelemetryHash } from "./normalize";
import { compileDetectionRule, evaluateSequence, evaluateThreshold, evaluateAnomaly, matchRuleNode } from "./dsl";
import { computeIndicatorConfidence, indicatorIsActiveForDetection, normalizeIndicatorValue, parseStixBundle } from "./intel";
import { socAlertFingerprint, computeAlertPriority } from "./alerts";
import { evaluateResponsePolicy, getResponseActionDefinition } from "./response";
import { validatePlaybookSteps, PLAYBOOK_TEMPLATES } from "./playbooks";
import { DETECTION_TEMPLATES, getDetectionTemplate } from "./templates";
import { computeDetectionCoverage } from "./coverage";
import { answerAttributionQuestion, composeIncidentSummary, translateSocNaturalQuery } from "./ai";
import type { CanonicalTelemetryEvent } from "./types";

function ev(partial: Partial<CanonicalTelemetryEvent>): CanonicalTelemetryEvent {
  return {
    eventTime: "2026-10-08T00:00:00.000Z", source: "test", sourceCategory: "AUTHENTICATION",
    eventCategory: "AUTHENTICATION", eventAction: "LOGIN", severity: "INFO",
    classification: "INTERNAL", attributes: {}, schemaVersion: "1.0", ...partial,
  };
}

describe("telemetry normalization (§5/§11/§157)", () => {
  it("normalizes an authentication event and fingerprints by provider id", () => {
    const out = normalizeTelemetryEvent({
      id: "evt-1", source: "okta-fixture", sourceCategory: "AUTHENTICATION", timestamp: "2026-10-08T00:00:00Z",
      action: "LOGIN", user: "rudra", outcome: "FAILURE", attributes: { token: "FAKE_TOKEN_123" },
    });
    expect(out.ok).toBe(true);
    expect(out.event?.identityReference).toBe("rudra");
    // planted fake secret is scrubbed before storage (§157)
    expect(JSON.stringify(out.event)).not.toContain("FAKE_TOKEN_123");
    expect(out.fingerprint).toBe("prov:okta-fixture:evt-1");
  });

  it("duplicate provider event yields the same fingerprint (§129)", () => {
    const raw = { eventId: "dup-1", sourceCategory: "DNS", eventTime: "2026-10-08T00:00:00Z", eventAction: "QUERY" };
    expect(normalizeTelemetryEvent(raw).fingerprint).toBe(normalizeTelemetryEvent(raw).fingerprint);
  });

  it("content hash detects tampering (§7/§143)", () => {
    const out = normalizeTelemetryEvent({ eventId: "h1", sourceCategory: "DNS", eventTime: "2026-10-08T00:00:00Z", eventAction: "QUERY" });
    expect(verifyTelemetryHash(out.event!, out.contentHash!)).toBe(true);
    const tampered = { ...out.event!, eventAction: "CHANGED" };
    expect(verifyTelemetryHash(tampered, out.contentHash!)).toBe(false);
  });

  it("fingerprint is stable for id-less events", () => {
    const e = ev({});
    expect(telemetryFingerprint(e)).toBe(telemetryFingerprint(e));
  });
});

describe("detection DSL (§17–§24)", () => {
  it("compiles every shipped template", () => {
    for (const t of DETECTION_TEMPLATES) {
      const compiled = compileDetectionRule(t.definition);
      expect(compiled.ok, `${t.key}: ${compiled.errors.join(",")}`).toBe(true);
    }
    expect(DETECTION_TEMPLATES.length).toBeGreaterThanOrEqual(15);
    expect(getDetectionTemplate("auth-failure-burst")?.attack[0].techniqueId).toBe("T1110");
  });

  it("rejects rules containing shell/SQL/eval content (§134)", () => {
    for (const bad of [
      { type: "SINGLE_EVENT", conditions: { kind: "cond", field: "eventAction", op: "eq", value: "x; DROP TABLE alerts" } },
      { type: "SINGLE_EVENT", conditions: { kind: "cond", field: "eventAction", op: "eq", value: "eval(payload)" } },
      { type: "SINGLE_EVENT", conditions: { kind: "cond", field: "attributes.shell", op: "exists" } },
      { type: "SINGLE_EVENT", conditions: { kind: "cond", field: "eventAction`id`", op: "eq", value: "x" } },
    ]) {
      expect(compileDetectionRule(bad).ok).toBe(false);
    }
  });

  it("rejects excessive complexity (§135)", () => {
    const deep = { kind: "all", children: [{ kind: "all", children: [{ kind: "all", children: [{ kind: "all", children: [{ kind: "all", children: [{ kind: "cond", field: "severity", op: "eq", value: "HIGH" }] }] }] }] }] };
    expect(compileDetectionRule({ type: "SINGLE_EVENT", conditions: deep }).errors).toContain("RULE_TOO_DEEP");
    expect(compileDetectionRule({ type: "THRESHOLD", windowSeconds: 5, threshold: { count: 3 }, conditions: { kind: "cond", field: "severity", op: "eq", value: "HIGH" } }).ok).toBe(false);
    expect(compileDetectionRule({ type: "SINGLE_EVENT", conditions: { kind: "cond", field: "rawSql", op: "eq", value: "x" } }).ok).toBe(false);
  });

  it("single-event match and non-match (§130/§131)", () => {
    const def = compileDetectionRule(getDetectionTemplate("critical-control-disabled")!.definition).definition!;
    expect(matchRuleNode(def.conditions, ev({ eventAction: "CONTROL_DISABLED", eventCategory: "POLICY" }))).toBe(true);
    expect(matchRuleNode(def.conditions, ev({ eventAction: "LOGIN" }))).toBe(false);
  });

  it("threshold: below threshold no match, at threshold match (§132)", () => {
    const def = compileDetectionRule(getDetectionTemplate("auth-failure-burst")!.definition).definition!;
    const fail = (min: number) => ev({ eventTime: `2026-10-08T00:0${min}:00.000Z`, identityReference: "rudra", attributes: { outcome: "FAILURE" } });
    expect(evaluateThreshold(def, [fail(0), fail(1), fail(2), fail(3)])).toHaveLength(0);
    const matches = evaluateThreshold(def, [fail(0), fail(1), fail(2), fail(3), fail(4)]);
    expect(matches).toHaveLength(1);
    expect(matches[0].count).toBe(5);
    expect(matches[0].groupKey).toBe("rudra");
  });

  it("sequence: ordered chain matches, wrong order does not (§133)", () => {
    const def = compileDetectionRule(getDetectionTemplate("privilege-then-sensitive-access")!.definition).definition!;
    const t = (min: number) => `2026-10-08T00:${String(min).padStart(2, "0")}:00.000Z`;
    const chain = [
      ev({ eventTime: t(1), attributes: { unexpected: true } }),
      ev({ eventTime: t(2), eventCategory: "IDENTITY", eventAction: "ROLE_GRANTED" }),
      ev({ eventTime: t(3), eventCategory: "DATA", eventAction: "SENSITIVE_RESOURCE_ACCESS" }),
    ];
    expect(evaluateSequence(def, chain)).not.toBeNull();
    const wrongOrder = [chain[2], chain[0], chain[1]].map((e, i) => ({ ...e, eventTime: t(i + 1) }));
    // wrong order: sensitive access happens FIRST in time
    expect(evaluateSequence(def, wrongOrder)).toBeNull();
  });

  it("anomaly signal is explainable and needs a baseline (§20)", () => {
    const def = compileDetectionRule({
      type: "ANOMALY_SIGNAL", conditions: { kind: "cond", field: "eventCategory", op: "exists" },
      anomaly: { metricField: "attributes.bytesOut", minSamples: 30, zScore: 3 },
    }).definition!;
    const e = ev({ attributes: { bytesOut: 1000 } });
    const noBase = evaluateAnomaly(def, e, { mean: 100, stdDev: 10, samples: 3 });
    expect(noBase.matched).toBe(false);
    expect(noBase.reason).toContain("insufficient baseline");
    const hit = evaluateAnomaly(def, e, { mean: 100, stdDev: 10, samples: 100 });
    expect(hit.matched).toBe(true);
    expect(hit.reason).toContain("z=");
  });
});

describe("threat intelligence (§55–§66)", () => {
  it("normalizes indicator values strictly", () => {
    expect(normalizeIndicatorValue("IP", "203.0.113.7")).toBe("203.0.113.7");
    expect(normalizeIndicatorValue("IP", "999.1.1.1")).toBeNull();
    expect(normalizeIndicatorValue("DOMAIN", "Evil.Example.COM.")).toBe("evil.example.com");
    expect(normalizeIndicatorValue("FILE_HASH", "A".repeat(64))).toBe("a".repeat(64));
    expect(normalizeIndicatorValue("FILE_HASH", "xyz")).toBeNull();
    expect(normalizeIndicatorValue("URL", "javascript:alert(1)")).toBeNull();
  });

  it("parses a STIX bundle with provenance (§60)", () => {
    const bundle = {
      type: "bundle", objects: [
        { type: "indicator", id: "indicator--1", pattern: "[domain-name:value = 'evil.example']", confidence: 80, labels: ["malicious-activity"], valid_from: "2026-10-01T00:00:00Z" },
        { type: "indicator", id: "indicator--2", pattern: "[ipv4-addr:value = '203.0.113.9']" },
        { type: "malware", id: "malware--1", name: "ignored" },
        { type: "indicator", id: "indicator--3", pattern: "not a pattern" },
      ],
    };
    const parsed = parseStixBundle(bundle);
    expect(parsed.indicators).toHaveLength(2);
    expect(parsed.indicators[0]).toMatchObject({ type: "DOMAIN", valueNormalized: "evil.example", confidence: 80 });
    expect(parsed.skipped).toBe(2);
  });

  it("confidence is deterministic: trust × recency + corroboration (§63)", () => {
    const now = new Date("2026-10-08T00:00:00Z");
    expect(computeIndicatorConfidence({ sourceTrust: 90, observedAt: now, now, independentSourceCount: 1 })).toBe(90);
    expect(computeIndicatorConfidence({ sourceTrust: 90, observedAt: now, now, independentSourceCount: 3 })).toBe(100);
    expect(computeIndicatorConfidence({ sourceTrust: 90, observedAt: new Date("2026-01-01T00:00:00Z"), now, independentSourceCount: 1 })).toBe(36);
  });

  it("expired indicators produce no active detections by default (§139)", () => {
    const now = new Date("2026-10-08T00:00:00Z");
    expect(indicatorIsActiveForDetection({ status: "ACTIVE", validUntil: new Date("2026-10-01T00:00:00Z"), now })).toBe(false);
    expect(indicatorIsActiveForDetection({ status: "EXPIRED", now })).toBe(false);
    expect(indicatorIsActiveForDetection({ status: "ACTIVE", validUntil: new Date("2027-01-01T00:00:00Z"), now })).toBe(true);
    expect(indicatorIsActiveForDetection({ status: "REVOKED", now })).toBe(false);
  });
});

describe("alerts (§32–§35)", () => {
  it("fingerprint is stable for equivalent detections (§136)", () => {
    const a = socAlertFingerprint({ ruleId: "r1", ruleVersion: 2, groupKey: "rudra" });
    expect(a).toBe(socAlertFingerprint({ ruleId: "r1", ruleVersion: 2, groupKey: "rudra" }));
    expect(a).not.toBe(socAlertFingerprint({ ruleId: "r1", ruleVersion: 3, groupKey: "rudra" }));
  });

  it("priority engine weighs KEV + criticality + exposure (§34)", () => {
    const hot = computeAlertPriority({ severity: "CRITICAL", confidence: "HIGH", assetCriticality: "CRITICAL", internetExposed: true, kev: true });
    expect(hot.priority).toBe("P1");
    const mild = computeAlertPriority({ severity: "LOW", confidence: "LOW" });
    expect(mild.priority).toBe("P4");
    expect(hot.factors.kev).toBe(15);
  });
});

describe("response policy (§74–§82/§126)", () => {
  it("catalog is closed and predefined (§76)", () => {
    expect(getResponseActionDefinition("DISABLE_DSRCLONE_API_KEY")?.approvalMode).toBe("SINGLE_APPROVAL");
    expect(getResponseActionDefinition("RUN_SHELL_COMMAND")).toBeNull();
    expect(getResponseActionDefinition("GENERIC_HTTP_POST")).toBeNull();
  });

  it("proposer cannot approve their own high-impact action (§126)", () => {
    const out = evaluateResponsePolicy({ actionKey: "DISABLE_DSRCLONE_API_KEY", proposerId: "u1", approvals: [{ approverId: "u1", decision: "APPROVED" }] });
    expect(out.eligible).toBe(false);
    expect(out.reasons).toContain("SOD_PROPOSER_CANNOT_APPROVE");
  });

  it("dual approval needs two distinct approvers (§147)", () => {
    const one = evaluateResponsePolicy({ actionKey: "PAUSE_DSRCLONE_INTEGRATION", proposerId: "u1", approvals: [{ approverId: "u2", decision: "APPROVED" }] });
    expect(one.eligible).toBe(false);
    const two = evaluateResponsePolicy({ actionKey: "PAUSE_DSRCLONE_INTEGRATION", proposerId: "u1", approvals: [{ approverId: "u2", decision: "APPROVED" }, { approverId: "u3", decision: "APPROVED" }] });
    expect(two.eligible).toBe(true);
  });
});

describe("playbooks (§83–§89/§150)", () => {
  it("all shipped templates validate", () => {
    for (const p of PLAYBOOK_TEMPLATES) expect(validatePlaybookSteps(p.steps).ok, p.key).toBe(true);
    expect(PLAYBOOK_TEMPLATES.length).toBe(7);
  });

  it("executable steps are rejected (§150)", () => {
    const bad = [{ key: "x", title: "x", category: "INVESTIGATE", description: "x", command: "rm -rf /" }];
    expect(validatePlaybookSteps(bad).ok).toBe(false);
    const badCategory = [{ key: "x", title: "x", category: "RUN_CODE", description: "x" }];
    expect(validatePlaybookSteps(badCategory).ok).toBe(false);
  });
});

describe("coverage + AI (§112/§151/§101)", () => {
  it("coverage counts only ACTIVE + tested rules (§113)", () => {
    const cov = computeDetectionCoverage([
      { id: "r1", status: "ACTIVE", tested: true, attack: getDetectionTemplate("auth-failure-burst")!.attack, dataSources: ["AUTHENTICATION"], evaluationFailures: 0, matchCount: 3, falsePositiveCount: 0, triagedCount: 2 },
      { id: "r2", status: "DRAFT", tested: false, attack: getDetectionTemplate("new-kev-exposure")!.attack, dataSources: ["DSRCLONE_INTERNAL"], evaluationFailures: 0, matchCount: 0, falsePositiveCount: 0, triagedCount: 0 },
    ]);
    expect(cov.techniques.find((t) => t.techniqueId === "T1110")?.covered).toBe(true);
    expect(cov.techniques.find((t) => t.techniqueId === "T1190")?.covered).toBe(false);
    expect(cov.note).toContain("does not imply");
  });

  it("attribution question with no intel is refused (§151)", () => {
    const ans = answerAttributionQuestion({ incident: null, alerts: [], events: [], assets: [], identities: [], indicators: [], timeline: [], actionsTaken: [] });
    expect(ans.status).toBe("INSUFFICIENT_EVIDENCE");
    expect(ans.attribution.claimed).toBe(false);
  });

  it("incident summary is grounded and never attributes (§100/§99)", () => {
    const ans = composeIncidentSummary({
      incident: { id: "inc-1", title: "Test", status: "INVESTIGATING", severity: "HIGH", priority: "P1" },
      alerts: [{ id: "a1", title: "burst", severity: "HIGH", status: "NEW" }],
      events: [], assets: [], identities: ["rudra"], indicators: [], timeline: [], actionsTaken: [],
    });
    expect(ans.status).toBe("OK");
    expect(ans.citations).toContainEqual({ kind: "INCIDENT", id: "inc-1" });
    expect(ans.attribution.claimed).toBe(false);
  });

  it("NL queries translate deterministically (§101)", () => {
    expect(translateSocNaturalQuery("Show P1 alerts from privileged identities")).toEqual({ kind: "ALERTS", filters: { priority: "P1", identityPrivileged: true } });
    expect(translateSocNaturalQuery("Show incidents involving KEV assets")?.kind).toBe("INCIDENTS");
    expect(translateSocNaturalQuery("delete everything")).toBeNull();
  });
});
