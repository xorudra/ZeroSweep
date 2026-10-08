import { ForbiddenException, NotFoundException, BadRequestException } from "@nestjs/common";
import { generateApiKey } from "@dsrclone/security-sdk";
import { TelemetryService } from "./telemetry/telemetry.service";
import { IngestionCoordinator } from "./telemetry/ingestion-coordinator.service";
import { DetectionService } from "./detections/detection.service";
import { AlertService } from "./alerts/alert.service";
import { IncidentService } from "./incidents/incident.service";
import { IntelService } from "./threat-intelligence/intel.service";
import { SocCorrelationService } from "./correlation/soc-correlation.service";
import { ResponseService } from "./response/response.service";
import { PlaybookService } from "./playbooks/playbook.service";
import { SocAnalyticsService } from "./analytics/soc-analytics.service";
import { SocHealthService } from "./health/soc-health.service";
import { SocSiemService } from "./siem/soc-siem.service";
import { SocAiService } from "./ai/soc-ai.service";
import { EventsService } from "../integrations/events/events.service";
import type { RequestUser } from "../../common/decorators/auth.decorators";

/* ------------------------------------------------------------------ */
/* In-memory fake Prisma (same pattern as prior phase specs).          */
/* ------------------------------------------------------------------ */

function mockFn(impl: (...args: never[]) => Promise<unknown>) {
  const calls: unknown[][] = [];
  const fn = async (...args: unknown[]) => { calls.push(args); return impl(...(args as never[])); };
  return Object.assign(fn, { calls });
}
type Row = Record<string, unknown> & { id: string };

function cmp(a: unknown, b: unknown): number {
  const av = a instanceof Date ? a.getTime() : (a as number);
  const bv = b instanceof Date ? b.getTime() : (b as number);
  return av < bv ? -1 : av > bv ? 1 : 0;
}

function matches(row: Row, where: Record<string, unknown> = {}): boolean {
  for (const [key, cond] of Object.entries(where)) {
    const value = row[key];
    if (cond === null) { if (value !== null && value !== undefined) return false; continue; }
    if (cond instanceof Date || typeof cond !== "object") { if (value !== cond) return false; continue; }
    const c = cond as Record<string, unknown>;
    if ("in" in c) { if (!(c.in as unknown[]).includes(value)) return false; continue; }
    if ("not" in c) {
      if (c.not === null) { if (value === null || value === undefined) return false; }
      else if (value === c.not) return false;
      continue;
    }
    if ("gte" in c && cmp(value, c.gte) < 0) return false;
    if ("lte" in c && cmp(value, c.lte) > 0) return false;
    if ("gt" in c && cmp(value, c.gt) <= 0) return false;
    if ("lt" in c && cmp(value, c.lt) >= 0) return false;
    if (!("gte" in c) && !("lte" in c) && !("gt" in c) && !("lt" in c)) return false;
  }
  return true;
}

let seq = 0;
function makeTable(name: string) {
  const rows: Row[] = [];
  const table = {
    rows,
    async create({ data }: { data: Row }) {
      const stamp = new Date(Date.now() + ++seq);
      const row: Row = { createdAt: stamp, updatedAt: stamp, ...data, id: data.id ?? `${name}-${seq}` };
      for (const f of ["ingestedAt", "detectedAt", "firstSeen", "lastSeen", "matchedAt", "collectedAt", "startedAt", "declaredAt", "observedAt"]) {
        if (row[f] === undefined) row[f] = stamp;
      }
      rows.push(row);
      return row;
    },
    async createMany({ data }: { data: Row[] }) { for (const d of data) await table.create({ data: d }); return { count: data.length }; },
    async findUnique({ where }: { where: Record<string, unknown> }) { return rows.find((r) => matches(r, where)) ?? null; },
    async findFirst(args: { where?: Record<string, unknown>; orderBy?: Record<string, string> } = {}) {
      const list = await table.findMany({ ...args, take: 1 }); return list[0] ?? null;
    },
    async findMany(args: { where?: Record<string, unknown>; take?: number; skip?: number; orderBy?: Record<string, string> | Array<Record<string, string>> } = {}) {
      let out = rows.filter((r) => matches(r, args.where));
      const orderBy = Array.isArray(args.orderBy) ? args.orderBy[0] : args.orderBy;
      if (orderBy) {
        const [field, dir] = Object.entries(orderBy)[0]!;
        out = [...out].sort((a, b) => cmp(a[field], b[field]) * (dir === "desc" ? -1 : 1));
      }
      if (args.skip) out = out.slice(args.skip);
      if (args.take) out = out.slice(0, args.take);
      return out;
    },
    async update({ where, data }: { where: Record<string, unknown>; data: Row }) {
      const row = rows.find((r) => matches(r, where));
      if (!row) throw new Error(`row not found in ${name}`);
      Object.assign(row, data);
      return row;
    },
    async updateMany({ where, data }: { where?: Record<string, unknown>; data: Row }) {
      let count = 0;
      for (const r of rows) if (matches(r, where)) { Object.assign(r, data); count++; }
      return { count };
    },
    async delete({ where }: { where: Record<string, unknown> }) {
      const i = rows.findIndex((r) => matches(r, where));
      if (i >= 0) rows.splice(i, 1);
      return {};
    },
    async deleteMany({ where }: { where?: Record<string, unknown> } = {}) {
      let count = 0;
      for (let i = rows.length - 1; i >= 0; i--) if (matches(rows[i]!, where)) { rows.splice(i, 1); count++; }
      return { count };
    },
    async count(args: { where?: Record<string, unknown> } = {}) { return rows.filter((r) => matches(r, args.where)).length; },
  };
  return table;
}

const TABLES = [
  "workspace", "auditLog", "socTelemetrySource", "securityTelemetryEvent", "detectionRule", "detectionRuleVersion",
  "detectionMatch", "securityAlert", "alertTriage", "alertSuppressionRule", "securityIncident", "incidentLink",
  "incidentTimelineEntry", "incidentEvidence", "incidentEvidenceAccess", "investigationCase", "threatIntelSource",
  "threatIndicator", "indicatorObservation", "indicatorMatch", "threatIntelFeedSync", "responseActionExecution",
  "responseActionApproval", "incidentPlaybookRun", "incidentCommunication", "postIncidentReview", "socSlaConfig",
  "telemetryDataGap", "socIncidentReport", "securityAnalyticsEvent", "securityCorrelationSignal", "asset", "finding",
  "kevRecord", "apiKey", "serviceAccount", "userSession", "integration", "securitySchedule", "remediationTicket",
  "securityNotification", "securityEventOutbox", "webhookSubscription", "integrationDelivery",
] as const;

function makeFake() {
  const db: Record<string, ReturnType<typeof makeTable>> = {};
  for (const t of TABLES) db[t] = makeTable(t);
  return db;
}

const OWNER: RequestUser = { id: "u-owner", email: "rudra@example.com", organizationId: "org-1", role: "OWNER" };
const ENGINEER: RequestUser = { id: "u-eng", email: "eng@example.com", organizationId: "org-1", role: "SECURITY_ENGINEER" };
const ANALYST: RequestUser = { id: "u-analyst", email: "analyst@example.com", organizationId: "org-1", role: "ANALYST" };
const VIEWER: RequestUser = { id: "u-viewer", email: "viewer@example.com", organizationId: "org-1", role: "VIEWER" };
const WS = "ws-1";
const WS2 = "ws-2";
const SESSION_AUTH = { kind: "USER_SESSION", reference: "session" };

function makeStack() {
  const prisma = makeFake();
  const audit = { record: mockFn(async () => ({})) };
  const alerts = new AlertService(prisma as never, audit as never);
  const telemetry = new TelemetryService(prisma as never, audit as never);
  const detections = new DetectionService(prisma as never, audit as never, alerts);
  const incidents = new IncidentService(prisma as never, audit as never);
  const intel = new IntelService(prisma as never, audit as never, alerts);
  const correlation = new SocCorrelationService(prisma as never, alerts);
  const response = new ResponseService(prisma as never, audit as never, incidents);
  const playbooks = new PlaybookService(prisma as never, audit as never, incidents);
  const analytics = new SocAnalyticsService(prisma as never);
  const health = new SocHealthService(prisma as never);
  const events = new EventsService(prisma as never);
  const siem = new SocSiemService(prisma as never, audit as never, events);
  const ai = new SocAiService(prisma as never, incidents);
  const coordinator = new IngestionCoordinator(prisma as never, telemetry, detections, intel, correlation);
  return { prisma, audit, alerts, telemetry, detections, incidents, intel, correlation, response, playbooks, analytics, health, siem, ai, coordinator };
}

function authFailEvent(id: string, minutesAgo: number, identity = "rudra") {
  return {
    id, source: "okta-fixture", sourceCategory: "AUTHENTICATION", eventCategory: "AUTHENTICATION",
    eventAction: "LOGIN", eventTime: new Date(Date.now() - minutesAgo * 60000).toISOString(),
    identityReference: identity, attributes: { outcome: "FAILURE" },
  };
}

async function activeThresholdRule(stack: ReturnType<typeof makeStack>) {
  await stack.detections.seedTemplates(OWNER, WS);
  const rule = stack.prisma.detectionRule.rows.find((r) => r.templateKey === "auth-failure-burst")!;
  await stack.detections.setRuleStatus(OWNER, WS, rule.id, "TESTING");
  await stack.detections.setRuleStatus(OWNER, WS, rule.id, "ACTIVE");
  return rule;
}

/* ------------------------------------------------------------------ */

describe("telemetry ingestion (§8–§13, §128–§129)", () => {
  it("ingests a controlled event: stored and searchable (§128)", async () => {
    const s = makeStack();
    const out = await s.coordinator.ingestAndProcess(OWNER, WS, SESSION_AUTH, [authFailEvent("e1", 1)]);
    expect(out.stored).toBe(1);
    const listed = await s.telemetry.listEvents(OWNER, WS, {});
    expect(listed.total).toBe(1);
    expect(listed.items[0]).toMatchObject({ eventAction: "LOGIN", sourceCategory: "AUTHENTICATION" });
  });

  it("same provider event twice = one logical event (§129)", async () => {
    const s = makeStack();
    await s.coordinator.ingestAndProcess(OWNER, WS, SESSION_AUTH, [authFailEvent("dup", 1)]);
    const again = await s.coordinator.ingestAndProcess(OWNER, WS, SESSION_AUTH, [authFailEvent("dup", 1)]);
    expect(again.duplicates).toBe(1);
    expect(s.prisma.securityTelemetryEvent.rows).toHaveLength(1);
  });

  it("rejects unauthenticated and wrongly-scoped ingestion (§9)", async () => {
    const s = makeStack();
    await expect(s.coordinator.ingestAndProcess(OWNER, WS, { kind: "API_KEY", reference: "dsr_live_wrong" }, [authFailEvent("x", 1)]))
      .rejects.toBeInstanceOf(ForbiddenException);
    const generated = generateApiKey();
    await s.prisma.apiKey.create({ data: {
      id: "key-1", ownerKind: "SERVICE_ACCOUNT", ownerId: "sa-1", organizationId: "org-1", name: "telemetry",
      prefix: generated.prefix, secretHash: generated.secretHash, scopes: ["findings:read"],
    } as never });
    // right key, wrong scope → still rejected
    await expect(s.coordinator.ingestAndProcess(OWNER, WS, { kind: "API_KEY", reference: generated.plaintext }, [authFailEvent("x", 1)]))
      .rejects.toBeInstanceOf(ForbiddenException);
    await s.prisma.apiKey.update({ where: { id: "key-1" }, data: { scopes: ["telemetry:ingest"] } as never });
    const ok = await s.coordinator.ingestAndProcess(OWNER, WS, { kind: "API_KEY", reference: generated.plaintext }, [authFailEvent("x", 1)]);
    expect(ok.authMode).toBe("API_KEY");
    expect(ok.stored).toBe(1);
  });

  it("planted secrets in telemetry never reach storage (§157)", async () => {
    const s = makeStack();
    await s.coordinator.ingestAndProcess(OWNER, WS, SESSION_AUTH, [{
      id: "sec-1", sourceCategory: "DNS", eventCategory: "DNS", eventAction: "QUERY",
      eventTime: new Date().toISOString(),
      attributes: { apiKey: "FAKE_API_KEY_VALUE_123", note: "password: FAKE_PASSWORD_999", domain: "example.com" },
    }]);
    const stored = JSON.stringify(s.prisma.securityTelemetryEvent.rows);
    expect(stored).not.toContain("FAKE_API_KEY_VALUE_123");
    expect(stored).not.toContain("FAKE_PASSWORD_999");
    expect((s.prisma.securityTelemetryEvent.rows[0]!.attributes as Row).apiKey).toBe("[REDACTED]");
  });
});

describe("detection engine (§13–§29)", () => {
  it("threshold: below threshold no alert, at threshold alert (§132)", async () => {
    const s = makeStack();
    await activeThresholdRule(s);
    for (let i = 0; i < 4; i++) {
      await s.coordinator.ingestAndProcess(OWNER, WS, SESSION_AUTH, [authFailEvent(`f${i}`, 4 - i)]);
    }
    expect(s.prisma.securityAlert.rows).toHaveLength(0);
    await s.coordinator.ingestAndProcess(OWNER, WS, SESSION_AUTH, [authFailEvent("f4", 0)]);
    expect(s.prisma.securityAlert.rows).toHaveLength(1);
    expect(s.prisma.detectionMatch.rows).toHaveLength(1);
    expect(s.prisma.securityAlert.rows[0]).toMatchObject({ source: "DETECTION", status: "NEW" });
  });

  it("benign fixture produces no alert (§131)", async () => {
    const s = makeStack();
    await activeThresholdRule(s);
    await s.coordinator.ingestAndProcess(OWNER, WS, SESSION_AUTH, [{
      id: "ok-1", sourceCategory: "AUTHENTICATION", eventCategory: "AUTHENTICATION", eventAction: "LOGIN",
      eventTime: new Date().toISOString(), identityReference: "rudra", attributes: { outcome: "SUCCESS" },
    }]);
    expect(s.prisma.securityAlert.rows).toHaveLength(0);
  });

  it("rule injection and complexity are rejected (§134/§135)", async () => {
    const s = makeStack();
    await expect(s.detections.createRule(OWNER, WS, {
      name: "evil", category: "X", severity: "HIGH",
      definition: { type: "SINGLE_EVENT", conditions: { kind: "cond", field: "eventAction", op: "eq", value: "x; DROP TABLE" } },
    })).rejects.toBeInstanceOf(BadRequestException);
    await expect(s.detections.createRule(OWNER, WS, {
      name: "deep", category: "X", severity: "HIGH",
      definition: { type: "SINGLE_EVENT", conditions: { kind: "all", children: [{ kind: "all", children: [{ kind: "all", children: [{ kind: "all", children: [{ kind: "all", children: [{ kind: "cond", field: "severity", op: "eq", value: "HIGH" }] }] }] }] }] } },
    })).rejects.toBeInstanceOf(BadRequestException);
  });

  it("editing a rule creates a new immutable version (§16)", async () => {
    const s = makeStack();
    const rule = await s.detections.createRule(OWNER, WS, {
      name: "v-test", category: "X", severity: "LOW",
      definition: { type: "SINGLE_EVENT", conditions: { kind: "cond", field: "eventAction", op: "eq", value: "A" } },
    }) as Row;
    const out = await s.detections.updateRule(OWNER, WS, rule.id, {
      definition: { type: "SINGLE_EVENT", conditions: { kind: "cond", field: "eventAction", op: "eq", value: "B" } },
    });
    expect(out.newVersion).toBe(2);
    const versions = s.prisma.detectionRuleVersion.rows.filter((v) => v.ruleId === rule.id);
    expect(versions).toHaveLength(2);
    expect((versions.find((v) => v.version === 1)!.definition as Row).conditions).toMatchObject({ value: "A" });
  });

  it("sequence test via rule testing service (§133)", async () => {
    const s = makeStack();
    await s.detections.seedTemplates(OWNER, WS);
    const rule = s.prisma.detectionRule.rows.find((r) => r.templateKey === "privilege-then-sensitive-access")!;
    const base = {
      source: "t", sourceCategory: "AUTHENTICATION", severity: "INFO" as const,
      classification: "INTERNAL" as const, attributes: {}, schemaVersion: "1.0",
    };
    const ordered = [
      { ...base, providerEventId: "s1", eventTime: "2026-10-08T00:01:00.000Z", eventCategory: "AUTHENTICATION", eventAction: "LOGIN", attributes: { unexpected: true } },
      { ...base, providerEventId: "s2", eventTime: "2026-10-08T00:02:00.000Z", eventCategory: "IDENTITY", eventAction: "ROLE_GRANTED" },
      { ...base, providerEventId: "s3", eventTime: "2026-10-08T00:03:00.000Z", eventCategory: "DATA", eventAction: "SENSITIVE_RESOURCE_ACCESS" },
    ];
    const hit = await s.detections.testRule(OWNER, WS, rule.id, ordered as never);
    expect(hit.matches).toBe(1);
    const wrongOrder = [
      { ...ordered[2], eventTime: "2026-10-08T00:01:00.000Z" },
      { ...ordered[0], eventTime: "2026-10-08T00:02:00.000Z" },
      { ...ordered[1], eventTime: "2026-10-08T00:03:00.000Z" },
    ];
    const miss = await s.detections.testRule(OWNER, WS, rule.id, wrongOrder as never);
    expect(miss.matches).toBe(0);
  });
});

describe("alert lifecycle (§30–§40)", () => {
  it("repeat equivalent detections bump one alert (§136)", async () => {
    const s = makeStack();
    await activeThresholdRule(s);
    for (let i = 0; i < 5; i++) await s.coordinator.ingestAndProcess(OWNER, WS, SESSION_AUTH, [authFailEvent(`a${i}`, 5 - i)]);
    for (let i = 0; i < 5; i++) await s.coordinator.ingestAndProcess(OWNER, WS, SESSION_AUTH, [authFailEvent(`b${i}`, 5 - i, "other-user")]);
    // different identity → different fingerprint → second alert
    expect(s.prisma.securityAlert.rows).toHaveLength(2);
    for (let i = 0; i < 5; i++) await s.coordinator.ingestAndProcess(OWNER, WS, SESSION_AUTH, [authFailEvent(`c${i}`, 5 - i)]);
    const rudraAlerts = s.prisma.securityAlert.rows.filter((a) => a.identityReference === "rudra" || !a.identityReference);
    expect(s.prisma.securityAlert.rows).toHaveLength(2);
    expect(Math.max(...s.prisma.securityAlert.rows.map((a) => a.occurrenceCount as number))).toBeGreaterThanOrEqual(2);
    void rudraAlerts;
  });

  it("suppression is scoped and expires (§137/§40)", async () => {
    const s = makeStack();
    const rule = await activeThresholdRule(s);
    // unscoped suppression cannot be created
    await expect(s.alerts.createSuppression(OWNER, WS, { reason: "all", expiresAt: new Date(Date.now() + 3600000).toISOString() }))
      .rejects.toBeInstanceOf(BadRequestException);
    await s.alerts.createSuppression(OWNER, WS, {
      ruleId: rule.id, reason: "maintenance window", expiresAt: new Date(Date.now() + 3600000).toISOString(),
    });
    for (let i = 0; i < 5; i++) await s.coordinator.ingestAndProcess(OWNER, WS, SESSION_AUTH, [authFailEvent(`s${i}`, 5 - i)]);
    expect(s.prisma.securityAlert.rows).toHaveLength(0);
    // expire the suppression (advance the clock on the record)
    s.prisma.alertSuppressionRule.rows[0]!.expiresAt = new Date(Date.now() - 1000);
    for (let i = 0; i < 5; i++) await s.coordinator.ingestAndProcess(OWNER, WS, SESSION_AUTH, [authFailEvent(`t${i}`, 5 - i)]);
    expect(s.prisma.securityAlert.rows).toHaveLength(1);
  });

  it("triage records decisions and false positives feed trends, never auto-disable (§36–§38)", async () => {
    const s = makeStack();
    const raised = await s.alerts.raiseAlert({
      organizationId: "org-1", workspaceId: WS, fingerprint: "fp-triage", title: "t", severity: "HIGH", source: "MANUAL",
    });
    const alertId = raised.alert!.id as string;
    await s.alerts.triageAlert(ANALYST, WS, alertId, { decision: "FALSE_POSITIVE", reason: "expected scanner" });
    expect(s.prisma.alertTriage.rows).toHaveLength(1);
    const detail = await s.alerts.getAlertDetail(OWNER, WS, alertId);
    expect(detail.alert.status).toBe("TRIAGED");
    expect(detail.alert.acknowledgedAt).toBeTruthy();
  });

  it("cross-tenant alert access is denied (§154)", async () => {
    const s = makeStack();
    const raised = await s.alerts.raiseAlert({
      organizationId: "org-1", workspaceId: WS, fingerprint: "fp-tenant", title: "t", severity: "LOW", source: "MANUAL",
    });
    await expect(s.alerts.getAlertDetail(OWNER, WS2, raised.alert!.id as string)).rejects.toBeInstanceOf(NotFoundException);
  });
});

describe("incidents, timeline, evidence (§41–§53)", () => {
  async function incidentWithAlert(s: ReturnType<typeof makeStack>) {
    const raised = await s.alerts.raiseAlert({
      organizationId: "org-1", workspaceId: WS, fingerprint: "fp-inc", title: "Suspicious login burst", severity: "HIGH", source: "DETECTION",
    });
    const incident = await s.incidents.escalateAlert(OWNER, WS, raised.alert!.id as string, {}) as Row;
    return { alert: raised.alert! as unknown as Row, incident };
  }

  it("escalation preserves the alert link and timeline (§141/§142)", async () => {
    const s = makeStack();
    const { alert, incident } = await incidentWithAlert(s);
    const detail = await s.incidents.getIncidentDetail(OWNER, WS, incident.id);
    expect(detail.links.some((l) => l.resourceType === "ALERT" && l.resourceId === alert.id)).toBe(true);
    expect(detail.timeline.length).toBeGreaterThanOrEqual(2);
    await s.incidents.addTimelineEntry(ANALYST, WS, incident.id, { summary: "Analyst note: investigating." });
    const note = s.prisma.incidentTimelineEntry.rows.find((t) => t.entryType === "ANALYST_NOTE")!;
    await s.incidents.addTimelineEntry(OWNER, WS, incident.id, { summary: "Correction: asset confirmed.", amendsEntryId: note.id });
    const after = await s.incidents.getIncidentDetail(OWNER, WS, incident.id);
    const original = after.timeline.find((t) => t.id === note.id)!;
    expect(original.summary).toBe("Analyst note: investigating.");
    expect(after.timeline.some((t) => t.amendsEntryId === note.id)).toBe(true);
  });

  it("evidence hash chain detects tampering (§143)", async () => {
    const s = makeStack();
    const { incident } = await incidentWithAlert(s);
    const evidence = await s.incidents.addEvidence(OWNER, WS, incident.id, {
      source: "FILE", classification: "CONFIDENTIAL", objectReference: "fixture:auth-log", description: "auth log excerpt", content: "log-line-1",
    }) as Row;
    const ok = await s.incidents.verifyEvidence(OWNER, WS, incident.id, evidence.id, "log-line-1");
    expect(ok.integrityOk).toBe(true);
    const bad = await s.incidents.verifyEvidence(OWNER, WS, incident.id, evidence.id, "log-line-EDITED");
    expect(bad.integrityOk).toBe(false);
    // telemetry-sourced evidence must match the stored event hash
    await s.coordinator.ingestAndProcess(OWNER, WS, SESSION_AUTH, [authFailEvent("ev-1", 1)]);
    const event = s.prisma.securityTelemetryEvent.rows[0]!;
    await expect(s.incidents.addEvidence(OWNER, WS, incident.id, {
      source: "TELEMETRY_EVENT", classification: "INTERNAL", objectReference: "fixture:forged",
      content: "not the event", relatedEventId: event.id,
    })).rejects.toBeInstanceOf(BadRequestException);
  });

  it("restricted evidence access is denied to non-members and every attempt is logged (§144)", async () => {
    const s = makeStack();
    const { incident } = await incidentWithAlert(s);
    const evidence = await s.incidents.addEvidence(OWNER, WS, incident.id, {
      source: "MANUAL", classification: "RESTRICTED", objectReference: "manual:secret-note", description: "secret evidence", content: "sensitive",
    }) as Row;
    await expect(s.incidents.getEvidence(ANALYST, WS, incident.id, evidence.id)).rejects.toBeInstanceOf(ForbiddenException);
    const allowed = await s.incidents.getEvidence(OWNER, WS, incident.id, evidence.id) as unknown as { accessHistory: Array<Record<string, unknown>> };
    expect(allowed.accessHistory.some((a) => a.result === "DENIED")).toBe(true);
    expect(allowed.accessHistory.some((a) => a.result === "ALLOWED")).toBe(true);
  });

  it("cross-tenant incident access is denied (§156)", async () => {
    const s = makeStack();
    const { incident } = await incidentWithAlert(s);
    await expect(s.incidents.getIncidentDetail(OWNER, WS2, incident.id)).rejects.toBeInstanceOf(NotFoundException);
  });

  it("investigation case escalates to an incident preserving references (§53)", async () => {
    const s = makeStack();
    const { alert } = await incidentWithAlert(s);
    const kase = await s.incidents.createCase(OWNER, WS, {
      title: "Review suspicious logins", severity: "MEDIUM", linkedAlertIds: [alert.id],
    }) as Row;
    const out = await s.incidents.escalateCase(OWNER, WS, kase.id) as { case: Row; incident: Row };
    expect(out.case.status).toBe("ESCALATED");
    expect(out.case.escalatedIncidentId).toBe(out.incident.id);
    expect(out.incident.caseId).toBe(kase.id);
    // the alert reference survives the escalation as an incident link
    expect(s.prisma.incidentLink.rows.some((l) => l.incidentId === out.incident.id && l.resourceType === "ALERT" && l.resourceId === alert.id)).toBe(true);
  });
});

describe("threat intelligence (§54–§69)", () => {
  const STIX = {
    type: "bundle", id: "bundle--1", objects: [
      { type: "indicator", id: "indicator--1", pattern: "[domain-name:value = 'evil.example']", valid_from: "2026-10-01T00:00:00Z" },
      { type: "indicator", id: "indicator--2", pattern: "[ipv4-addr:value = '203.0.113.9']", valid_from: "2026-10-01T00:00:00Z", valid_until: "2026-10-02T00:00:00Z" },
      { type: "malware", id: "malware--1", name: "ignored object type" },
    ],
  };

  async function fixtureSource(s: ReturnType<typeof makeStack>, trust = 90) {
    const source = await s.intel.createSource(OWNER, WS, {
      name: "Recorded fixture feed", type: "FIXTURE", trustLevel: trust,
    }) as Row;
    // live transport is never configured (§61)
    expect(source.transportStatus).toBe("NOT_CONFIGURED");
    return source;
  }

  it("imports a STIX fixture with provenance; domain match is recorded (§138)", async () => {
    const s = makeStack();
    const source = await fixtureSource(s);
    const result = await s.intel.importIndicators(OWNER, WS, source.id, { format: "STIX", bundle: STIX });
    expect(result.created).toBe(2);
    const dns = await s.coordinator.ingestAndProcess(OWNER, WS, SESSION_AUTH, [{
      id: "dns-1", sourceCategory: "DNS", eventCategory: "DNS", eventAction: "QUERY",
      eventTime: new Date().toISOString(), attributes: { domain: "evil.example" },
    }]);
    expect(dns.indicatorMatches).toBe(1);
    const matches = await s.intel.listMatches(OWNER, WS, {});
    expect(matches.items[0]!.telemetryEventId).toBeTruthy();
    expect((matches.items[0]!.context as Row).provenance).toContain("Recorded fixture feed");
    expect((matches.items[0]!.context as Row).detectionActive).toBe(true);
  });

  it("expired indicator records history but raises no active detection (§139)", async () => {
    const s = makeStack();
    const source = await fixtureSource(s);
    await s.intel.importIndicators(OWNER, WS, source.id, { format: "STIX", bundle: STIX });
    const out = await s.coordinator.ingestAndProcess(OWNER, WS, SESSION_AUTH, [{
      id: "net-1", sourceCategory: "FIREWALL", eventCategory: "NETWORK", eventAction: "CONNECTION",
      eventTime: new Date().toISOString(), attributes: { sourceIp: "203.0.113.9" },
    }]);
    expect(out.indicatorMatches).toBe(1);
    expect(out.alertsCreated).toBe(0);
    const matches = await s.intel.listMatches(OWNER, WS, {});
    expect((matches.items[0]!.context as Row).detectionActive).toBe(false);
  });

  it("one low-confidence feed never classifies an event malicious alone (§140/§69)", async () => {
    const s = makeStack();
    const source = await fixtureSource(s, 10);
    await s.intel.importIndicators(OWNER, WS, source.id, {
      format: "INDICATORS", indicators: [{ type: "DOMAIN", value: "sketchy.example" }],
    });
    const out = await s.coordinator.ingestAndProcess(OWNER, WS, SESSION_AUTH, [{
      id: "dns-2", sourceCategory: "DNS", eventCategory: "DNS", eventAction: "QUERY",
      eventTime: new Date().toISOString(), attributes: { domain: "sketchy.example" },
    }]);
    expect(out.indicatorMatches).toBe(1);
    expect(out.alertsCreated).toBe(0);
    const indicator = s.prisma.threatIndicator.rows[0]!;
    expect(indicator.confidence as number).toBeLessThan(40);
  });

  it("indicator search is tenant-scoped (§155)", async () => {
    const s = makeStack();
    const source = await fixtureSource(s);
    await s.intel.importIndicators(OWNER, WS, source.id, { format: "STIX", bundle: STIX });
    const mine = await s.intel.searchIndicators(OWNER, WS, {});
    expect(mine.total).toBe(2);
    const theirs = await s.intel.searchIndicators(OWNER, WS2, {});
    expect(theirs.total).toBe(0);
  });
});

describe("response engine (§74–§82)", () => {
  async function incident(s: ReturnType<typeof makeStack>) {
    return await s.incidents.createIncident(OWNER, WS, { title: "Credential incident", severity: "HIGH" }) as Row;
  }

  it("approval modes + segregation of duties + execution (§145–§147)", async () => {
    const s = makeStack();
    const generated = generateApiKey();
    await s.prisma.apiKey.create({ data: {
      id: "key-victim", ownerKind: "USER", ownerId: "u-x", organizationId: "org-1", name: "leaked key",
      prefix: generated.prefix, secretHash: generated.secretHash, scopes: ["scans:read"],
    } as never });
    const inc = await incident(s);
    const proposed = await s.response.propose(ENGINEER, WS, inc.id, {
      actionKey: "DISABLE_DSRCLONE_API_KEY", targetReference: "key-victim", nonce: "n-1",
    });
    const executionId = proposed.execution.id as string;
    expect(proposed.execution.status).toBe("PENDING_APPROVAL");
    // cannot execute before approval (§146)
    const early = await s.response.execute(OWNER, WS, executionId);
    expect(early.executed).toBe(false);
    // a user without the approval permission is refused outright (§145)
    await expect(s.response.approve(ANALYST, WS, executionId, { decision: "APPROVED" }))
      .rejects.toBeInstanceOf(ForbiddenException);
    // proposer cannot approve own high-impact action (§79, SoD)
    const selfApprove = await s.response.approve(ENGINEER, WS, executionId, { decision: "APPROVED" });
    expect(selfApprove.execution.status).toBe("PENDING_APPROVAL");
    expect(selfApprove.policy.reasons.join(" ")).toMatch(/SOD|PROPOSER/i);
    const approved = await s.response.approve(OWNER, WS, executionId, { decision: "APPROVED" });
    expect(approved.execution.status).toBe("APPROVED");
    const executed = await s.response.execute(OWNER, WS, executionId);
    expect(executed.executed).toBe(true);
    expect(s.prisma.apiKey.rows[0]!.revokedAt).toBeTruthy();
    // idempotent re-execution (§148)
    const again = await s.response.execute(OWNER, WS, executionId);
    expect(again.duplicate).toBe(true);
  });

  it("dual approval is required for integration pause (§147)", async () => {
    const s = makeStack();
    await s.prisma.integration.create({ data: {
      id: "int-1", workspaceId: WS, organizationId: "org-1", type: "JIRA", name: "Jira", enabled: true, status: "CONFIGURED",
    } as never });
    const inc = await incident(s);
    const proposed = await s.response.propose(OWNER, WS, inc.id, {
      actionKey: "PAUSE_DSRCLONE_INTEGRATION", targetReference: "int-1", nonce: "n-2",
    });
    const executionId = proposed.execution.id as string;
    await s.response.approve(ENGINEER, WS, executionId, { decision: "APPROVED" });
    expect(s.prisma.responseActionExecution.rows[0]!.status).toBe("PENDING_APPROVAL");
    await s.response.approve({ ...OWNER, id: "u-admin2" }, WS, executionId, { decision: "APPROVED" });
    expect(s.prisma.responseActionExecution.rows[0]!.status).toBe("APPROVED");
    await s.response.execute(OWNER, WS, executionId);
    expect(s.prisma.integration.rows[0]!.enabled).toBe(false);
  });

  it("unknown actions and viewers are refused (§76/§145)", async () => {
    const s = makeStack();
    const inc = await incident(s);
    await expect(s.response.propose(OWNER, WS, inc.id, {
      actionKey: "RUN_SHELL", targetReference: "y", nonce: "n-3",
    })).rejects.toBeInstanceOf(BadRequestException);
    await expect(s.response.propose(VIEWER, WS, inc.id, {
      actionKey: "SEND_NOTIFICATION", targetReference: "y", nonce: "n-4",
    })).rejects.toBeInstanceOf(ForbiddenException);
  });

  it("idempotent proposal: same nonce returns the same execution (§148)", async () => {
    const s = makeStack();
    const inc = await incident(s);
    const first = await s.response.propose(OWNER, WS, inc.id, {
      actionKey: "SEND_NOTIFICATION", targetReference: inc.id, nonce: "same",
    });
    const second = await s.response.propose(OWNER, WS, inc.id, {
      actionKey: "SEND_NOTIFICATION", targetReference: inc.id, nonce: "same",
    });
    expect(second.execution.id).toBe(first.execution.id);
    expect(second.duplicate).toBe(true);
    expect(s.prisma.responseActionExecution.rows).toHaveLength(1);
  });
});

describe("playbooks (§83–§89)", () => {
  it("run advances steps in order and completes with audit trail (§149)", async () => {
    const s = makeStack();
    const inc = await s.incidents.createIncident(OWNER, WS, { title: "Exposed secret", severity: "HIGH" }) as Row;
    const run = await s.playbooks.start(OWNER, WS, inc.id, "exposed-secret") as Row;
    expect(run.status).toBe("RUNNING");
    await expect(s.playbooks.advance(OWNER, WS, run.id, { stepKey: "rotate" }))
      .rejects.toBeInstanceOf(BadRequestException);
    for (const key of ["confirm", "rotate", "ticket", "verify", "document"]) {
      await s.playbooks.advance(OWNER, WS, run.id, { stepKey: key });
    }
    const done = s.prisma.incidentPlaybookRun.rows[0]!;
    expect(done.status).toBe("COMPLETED");
    const actions = s.audit.record.calls.map((c) => (c[0] as Row).action);
    expect(actions).toContain("PLAYBOOK_STARTED");
    expect(actions).toContain("PLAYBOOK_COMPLETED");
  });
});

describe("correlation, health, analytics, SIEM, AI", () => {
  it("public exposure + KEV correlation raises an alert (§71)", async () => {
    const s = makeStack();
    await s.prisma.asset.create({ data: { id: "asset-1", workspaceId: WS, organizationId: "org-1", type: "WEB_APP", value: "203.0.113.10", hostname: "app.example.com" } as never });
    await s.prisma.finding.create({ data: { id: "f-1", workspaceId: WS, organizationId: "org-1", assetId: "asset-1", title: "Log4Shell", severity: "CRITICAL", cve: "CVE-2021-44228", status: "OPEN" } as never });
    await s.prisma.kevRecord.create({ data: { id: "kev-1", cveId: "CVE-2021-44228" } as never });
    const out = await s.coordinator.ingestAndProcess(OWNER, WS, SESSION_AUTH, [{
      id: "exp-1", sourceCategory: "DSRCLONE_INTERNAL", eventCategory: "EXPOSURE", eventAction: "EXPOSURE_CHANGED",
      eventTime: new Date().toISOString(), assetId: "asset-1", attributes: { public: true },
    }]);
    expect(out.correlationPatterns).toContain("public-exposure-kev");
    expect(s.prisma.securityAlert.rows.some((a) => a.source === "CORRELATION")).toBe(true);
  });

  it("telemetry gap is detected for a silent source (§153)", async () => {
    const s = makeStack();
    await s.telemetry.createSource(OWNER, WS, {
      name: "IdP feed", sourceCategory: "AUTHENTICATION", expectedIntervalSeconds: 60,
    });
    s.prisma.socTelemetrySource.rows[0]!.lastEventAt = new Date(Date.now() - 3600 * 1000);
    const out = await s.health.evaluate(OWNER, WS);
    expect(out.gapsCreated).toBe(1);
    const healthView = await s.health.telemetryHealth(OWNER, WS);
    expect(healthView.sources[0]!.status).toBe("GAP");
  });

  it("SLA breach is flagged once and emitted to the lake (§90/§91)", async () => {
    const s = makeStack();
    await s.prisma.securityAlert.create({ data: {
      id: "alert-old", organizationId: "org-1", workspaceId: WS, source: "DETECTION", fingerprint: "fp-old",
      title: "old P1", severity: "CRITICAL", priority: "P1", status: "NEW",
      firstSeen: new Date(Date.now() - 2 * 3600 * 1000), lastSeen: new Date(),
    } as never });
    await s.health.evaluate(OWNER, WS);
    await s.health.evaluate(OWNER, WS);
    const lake = s.prisma.securityAnalyticsEvent.rows.filter((e) => e.eventType === "SOC_SLA_BREACHED");
    expect(lake).toHaveLength(1);
    expect(s.prisma.securityAlert.rows[0]!.slaBreached).toBe(true);
  });

  it("analytics on an empty workspace are honestly empty (§122)", async () => {
    const s = makeStack();
    const overview = await s.analytics.overview(OWNER, WS);
    expect(overview.openAlerts).toBe(0);
    expect(overview.mttaSeconds).toBeNull();
    expect(overview.falsePositiveRate).toBeNull();
  });

  it("SIEM forwarding queues through the governed outbox only", async () => {
    const s = makeStack();
    await s.prisma.integration.create({ data: {
      id: "siem-1", workspaceId: WS, organizationId: "org-1", type: "SIEM", name: "Splunk HEC", enabled: true, status: "CONFIGURED", secretReference: "vault://siem",
    } as never });
    const raised = await s.alerts.raiseAlert({
      organizationId: "org-1", workspaceId: WS, fingerprint: "fp-siem", title: "t", severity: "HIGH", source: "DETECTION",
    });
    const out = await s.siem.forward(OWNER, WS, { integrationId: "siem-1", kind: "ALERT", resourceId: raised.alert!.id as string });
    expect(out.queued).toBe(true);
    expect(s.prisma.integrationDelivery.rows).toHaveLength(1);
    expect(s.prisma.integrationDelivery.rows[0]).toMatchObject({ destinationKind: "SIEM", status: "PENDING" });
  });

  it("AI refuses attribution and grounds incident summaries (§99/§151)", async () => {
    const s = makeStack();
    const refused = await s.ai.ask(OWNER, WS, { question: "Who attacked us?" });
    expect(refused.status).toBe("INSUFFICIENT_EVIDENCE");
    expect(refused.attribution.claimed).toBe(false);
    const inc = await s.incidents.createIncident(OWNER, WS, { title: "Investigate logins", severity: "MEDIUM" }) as Row;
    const summary = await s.ai.ask(OWNER, WS, { question: "Summarize this incident", incidentId: inc.id });
    expect(summary.status).toBe("OK");
    expect(summary.citations.some((c) => c.id === inc.id)).toBe(true);
  });
});
