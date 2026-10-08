import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  socAlertFingerprint, compileDetectionRule, computeDetectionCoverage, computeDetectionHealth,
  detectionConfidence, evaluateAnomaly, evaluateSequence, evaluateThreshold,
  getDetectionTemplate, matchRuleNode, DETECTION_TEMPLATES,
  type CanonicalTelemetryEvent, type DetectionRuleDefinition,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireSocPermission } from "../permissions";
import { AlertService } from "../alerts/alert.service";
import type { Row } from "../helpers";

type RuleRow = Row & { id: string };

/**
 * Detection engine (Prompt 28 §13–§29, §107–§114). Rules are
 * declarative DSL compiled by the SDK; published versions are
 * immutable (§16); evaluation runs over canonical telemetry stored
 * in THIS workspace only. Matches raise alerts through the single
 * AlertService path so dedupe/suppression/priority stay uniform.
 */
@Injectable()
export class DetectionService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly alerts: AlertService,
  ) {}

  /** Seed the §25 templates into a workspace as DRAFT rules (idempotent). */
  async seedTemplates(user: RequestUser, workspaceId: string) {
    requireSocPermission(user, "MANAGE_DETECTIONS");
    let created = 0;
    for (const template of DETECTION_TEMPLATES) {
      const existing = await this.prisma.detectionRule.findFirst({ where: { workspaceId, templateKey: template.key } });
      if (existing) continue;
      const rule = await this.prisma.detectionRule.create({
        data: {
          organizationId: user.organizationId, workspaceId, templateKey: template.key,
          name: template.name, description: template.description, category: template.category,
          severity: template.severity, status: "DRAFT", currentVersion: 1,
          attackMappings: template.attack as never, dataSources: template.dataSources as never,
          createdBy: user.id,
        },
      });
      await this.prisma.detectionRuleVersion.create({
        data: { ruleId: rule.id as string, version: 1, definition: template.definition as never, createdBy: user.id },
      });
      created++;
    }
    return { created, total: DETECTION_TEMPLATES.length };
  }

  async createRule(user: RequestUser, workspaceId: string, body: {
    name: string; description?: string; category: string; severity: string;
    templateKey?: string; definition: unknown; attackMappings?: unknown[]; dataSources?: string[];
  }) {
    requireSocPermission(user, "MANAGE_DETECTIONS");
    const template = body.templateKey ? getDetectionTemplate(body.templateKey) : null;
    const definition = body.definition ?? template?.definition;
    if (!definition) throw new BadRequestException("A rule definition (or a known templateKey) is required");
    const compiled = compileDetectionRule(definition);
    if (!compiled.ok) throw new BadRequestException({ message: "Detection rule rejected", errors: compiled.errors });
    const rule = await this.prisma.detectionRule.create({
      data: {
        organizationId: user.organizationId, workspaceId, templateKey: body.templateKey,
        name: body.name, description: body.description ?? template?.description ?? "", category: body.category,
        severity: body.severity, status: "DRAFT", currentVersion: 1,
        attackMappings: (body.attackMappings ?? template?.attack ?? []) as never,
        dataSources: (body.dataSources ?? template?.dataSources ?? []) as never,
        createdBy: user.id,
      },
    });
    await this.prisma.detectionRuleVersion.create({
      data: { ruleId: rule.id as string, version: 1, definition: compiled.definition as never, createdBy: user.id },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "DETECTION_RULE_CREATED", resourceType: "DetectionRule", resourceId: rule.id as string,
      metadata: { name: body.name, version: 1 },
    });
    return rule;
  }

  async listRules(user: RequestUser, workspaceId: string) {
    requireSocPermission(user, "VIEW_SOC");
    const items = await this.prisma.detectionRule.findMany({
      where: { workspaceId }, orderBy: { name: "asc" },
    });
    const enriched = [];
    for (const rule of items as RuleRow[]) {
      enriched.push({
        ...rule,
        falsePositiveRate: await this.falsePositiveRate(workspaceId, rule.id),
      });
    }
    return { items: enriched, total: enriched.length };
  }

  async falsePositiveRate(workspaceId: string, ruleId: string): Promise<number | null> {
    const alerts = await this.prisma.securityAlert.findMany({ where: { workspaceId, ruleId } });
    if ((alerts as Row[]).length === 0) return null;
    const alertIds = new Set((alerts as Row[]).map((a) => a.id as string));
    const triage = await this.prisma.alertTriage.findMany({ where: { workspaceId } });
    const rows = (triage as Row[]).filter((t) => alertIds.has(t.alertId as string));
    if (rows.length === 0) return null;
    const fp = rows.filter((t) => t.decision === "FALSE_POSITIVE").length;
    return Math.round((fp / rows.length) * 1000) / 1000;
  }

  async getRule(user: RequestUser, workspaceId: string, ruleId: string): Promise<RuleRow> {
    requireSocPermission(user, "VIEW_SOC");
    const rule = await this.prisma.detectionRule.findFirst({ where: { id: ruleId, workspaceId } });
    if (!rule) throw new NotFoundException("Detection rule not found in this workspace");
    return rule as RuleRow;
  }

  /** §16: editing creates a NEW immutable version; the old version
   *  row is never modified, and matches keep citing their version. */
  async updateRule(user: RequestUser, workspaceId: string, ruleId: string, body: {
    name?: string; description?: string; severity?: string; definition?: unknown;
    attackMappings?: unknown[]; dataSources?: string[];
  }) {
    requireSocPermission(user, "MANAGE_DETECTIONS");
    const rule = await this.getRule(user, workspaceId, ruleId);
    const data: Row = {};
    if (body.name !== undefined) data.name = body.name;
    if (body.description !== undefined) data.description = body.description;
    if (body.severity !== undefined) data.severity = body.severity;
    if (body.attackMappings !== undefined) data.attackMappings = body.attackMappings;
    if (body.dataSources !== undefined) data.dataSources = body.dataSources;
    let newVersion: number | null = null;
    if (body.definition !== undefined) {
      const compiled = compileDetectionRule(body.definition);
      if (!compiled.ok) throw new BadRequestException({ message: "Detection rule rejected", errors: compiled.errors });
      newVersion = (rule.currentVersion as number) + 1;
      await this.prisma.detectionRuleVersion.create({
        data: { ruleId, version: newVersion, definition: compiled.definition as never, createdBy: user.id },
      });
      data.currentVersion = newVersion;
      // An edited ACTIVE rule returns to TESTING until re-activated (§111 workflow).
      if (rule.status === "ACTIVE") data.status = "TESTING";
    }
    const updated = await this.prisma.detectionRule.update({ where: { id: ruleId }, data: data as never });
    return { rule: updated, newVersion };
  }

  /** §111: DRAFT → TESTING → ACTIVE, DISABLED, DEPRECATED. */
  async setRuleStatus(user: RequestUser, workspaceId: string, ruleId: string, status: string) {
    const rule = await this.getRule(user, workspaceId, ruleId);
    if (status === "ACTIVE") {
      requireSocPermission(user, "ACTIVATE_DETECTIONS");
      if (!["TESTING", "DISABLED"].includes(rule.status as string)) {
        throw new BadRequestException(`Rule in status ${rule.status} cannot be activated — it must pass through TESTING first (§111)`);
      }
      const version = await this.currentVersion(rule);
      const compiled = compileDetectionRule(version.definition);
      if (!compiled.ok) throw new BadRequestException({ message: "Stored rule version no longer compiles", errors: compiled.errors });
    } else {
      requireSocPermission(user, "MANAGE_DETECTIONS");
    }
    const updated = await this.prisma.detectionRule.update({ where: { id: ruleId }, data: { status } as never });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: status === "ACTIVE" ? "DETECTION_RULE_ACTIVATED" : status === "DISABLED" ? "DETECTION_RULE_DISABLED" : "DETECTION_RULE_CREATED",
      resourceType: "DetectionRule", resourceId: ruleId, metadata: { status, from: rule.status },
    });
    return updated;
  }

  private async currentVersion(rule: RuleRow): Promise<Row> {
    const version = await this.prisma.detectionRuleVersion.findFirst({
      where: { ruleId: rule.id, version: rule.currentVersion as number },
    });
    if (!version) throw new NotFoundException("Rule version not found");
    return version as Row;
  }

  /** §109/§110: run a rule against supplied fixture/historical
   *  events — evaluation only, no alerts are created. */
  async testRule(user: RequestUser, workspaceId: string, ruleId: string, events: CanonicalTelemetryEvent[]) {
    requireSocPermission(user, "TEST_DETECTIONS");
    const rule = await this.getRule(user, workspaceId, ruleId);
    const version = await this.currentVersion(rule);
    const started = Date.now();
    const outcome = this.evaluateDefinition(version.definition as DetectionRuleDefinition, events, new Date());
    const falsePositiveCandidates = outcome.matches.filter((m) =>
      events.filter((e) => m.eventIds.includes(e.providerEventId ?? "")).every((e) => e.severity === "INFO"),
    ).length;
    return {
      ruleId, ruleVersion: rule.currentVersion,
      matches: outcome.matches.length,
      matchedEventGroups: outcome.matches,
      nonMatches: events.length - new Set(outcome.matches.flatMap((m) => m.eventIds)).size,
      falsePositiveCandidates,
      evaluationMs: Date.now() - started,
      errors: outcome.errors,
    };
  }

  private evaluateDefinition(definition: DetectionRuleDefinition, events: CanonicalTelemetryEvent[], now: Date): {
    matches: Array<{ eventIds: string[]; groupKey?: string; reason: string; confidence: ReturnType<typeof detectionConfidence> }>;
    errors: string[];
  } {
    const compiled = compileDetectionRule(definition);
    if (!compiled.ok) return { matches: [], errors: compiled.errors };
    const def = compiled.definition!;
    const matches: Array<{ eventIds: string[]; groupKey?: string; reason: string; confidence: ReturnType<typeof detectionConfidence> }> = [];
    const ref = (e: CanonicalTelemetryEvent) => e.providerEventId ?? `${e.eventTime}:${e.eventAction}`;
    if (def.type === "SINGLE_EVENT" || def.type === "CORRELATION") {
      for (const event of events) {
        if (matchRuleNode(def.conditions, event)) {
          matches.push({ eventIds: [ref(event)], reason: `single-event match on ${event.eventAction}`, confidence: detectionConfidence({ type: def.type, severity: event.severity }) });
        }
      }
    } else if (def.type === "THRESHOLD") {
      for (const m of evaluateThreshold(def, events)) {
        matches.push({
          eventIds: m.events.map(ref), groupKey: m.groupKey,
          reason: `${m.count} events matched within ${def.windowSeconds}s (threshold ${def.threshold?.count}) for group ${m.groupKey}`,
          confidence: detectionConfidence({ type: def.type, severity: m.events[0].severity, thresholdCount: m.count, thresholdRequired: def.threshold?.count }),
        });
      }
    } else if (def.type === "SEQUENCE") {
      const hit = evaluateSequence(def, events);
      if (hit) matches.push({ eventIds: hit.events.map(ref), reason: `ordered sequence of ${hit.events.length} steps completed within ${def.windowSeconds}s`, confidence: detectionConfidence({ type: def.type, severity: hit.events[0].severity }) });
    } else if (def.type === "ANOMALY_SIGNAL" && def.anomaly) {
      const values = events.map((e) => e.attributes[def.anomaly!.metricField.slice("attributes.".length)])
        .filter((v): v is number => typeof v === "number");
      if (values.length > 0) {
        const mean = values.reduce((a, b) => a + b, 0) / values.length;
        const variance = values.reduce((a, b) => a + (b - mean) ** 2, 0) / values.length;
        const baseline = { mean, stdDev: Math.sqrt(variance), samples: values.length };
        for (const event of events) {
          const out = evaluateAnomaly(def, event, baseline);
          if (out.matched) matches.push({ eventIds: [ref(event)], reason: out.reason, confidence: "MEDIUM" });
        }
      }
      void now;
    }
    return { matches, errors: [] };
  }

  /**
   * Evaluate ACTIVE workspace rules against one freshly stored
   * telemetry event (plus its bounded window context). Called by the
   * ingestion coordinator — never directly by clients.
   */
  async evaluateEvent(organizationId: string, workspaceId: string, eventRow: Row): Promise<{ matches: number; alertsCreated: number }> {
    const rules = await this.prisma.detectionRule.findMany({ where: { workspaceId, status: "ACTIVE" } });
    const event = this.toCanonical(eventRow);
    let matches = 0;
    let alertsCreated = 0;
    for (const rule of rules as RuleRow[]) {
      try {
        const version = await this.currentVersion(rule);
        const def = version.definition as DetectionRuleDefinition;
        let context: CanonicalTelemetryEvent[] = [event];
        if ((def.type === "THRESHOLD" || def.type === "SEQUENCE") && def.windowSeconds) {
          const since = new Date(new Date(event.eventTime).getTime() - def.windowSeconds * 1000);
          const rows = await this.prisma.securityTelemetryEvent.findMany({
            where: { workspaceId, eventTime: { gte: since, lte: new Date(event.eventTime) } },
            orderBy: { eventTime: "asc" }, take: 500,
          });
          context = (rows as Row[]).map((r) => this.toCanonical(r));
          if (!context.some((e) => e.providerEventId === event.providerEventId && e.eventTime === event.eventTime)) context.push(event);
        }
        const outcome = this.evaluateDefinition(def, context, new Date());
        await this.prisma.detectionRule.update({
          where: { id: rule.id }, data: { lastEvaluatedAt: new Date() } as never,
        }).catch(() => undefined);
        for (const match of outcome.matches) {
          // Only matches that INVOLVE the fresh event raise new state;
          // historical replays were already handled at their ingest.
          const freshRefs = new Set([event.providerEventId ?? `${event.eventTime}:${event.eventAction}`]);
          if (!match.eventIds.some((id) => freshRefs.has(id))) continue;
          matches++;
          const matchedRows = context.filter((e) => match.eventIds.includes(e.providerEventId ?? `${e.eventTime}:${e.eventAction}`));
          const first = matchedRows[0] ?? event;
          const matchRow = await this.prisma.detectionMatch.create({
            data: {
              organizationId, workspaceId, ruleId: rule.id, ruleVersion: rule.currentVersion as number,
              eventIds: match.eventIds as never, severity: rule.severity as string, confidence: match.confidence,
              reason: match.reason, assetId: first.assetId, identityReference: first.identityReference,
              groupKey: match.groupKey,
            },
          });
          await this.prisma.detectionRule.update({
            where: { id: rule.id },
            data: { matchCount: ((rule.matchCount as number) ?? 0) + 1, lastMatchedAt: new Date() } as never,
          }).catch(() => undefined);
          const fingerprint = socAlertFingerprint({
            ruleId: rule.id, ruleVersion: rule.currentVersion as number,
            groupKey: match.groupKey, assetId: first.assetId, identityReference: first.identityReference,
          });
          const raised = await this.alerts.raiseAlert({
            organizationId, workspaceId, fingerprint,
            title: rule.name as string, description: match.reason,
            severity: rule.severity as string, source: "DETECTION", ruleId: rule.id,
            assetId: first.assetId, identityReference: first.identityReference,
            confidence: match.confidence,
          });
          if (raised.alert) {
            await this.prisma.detectionMatch.update({
              where: { id: matchRow.id as string }, data: { alertId: raised.alert.id as string } as never,
            }).catch(() => undefined);
            if (raised.created) alertsCreated++;
          }
          await this.audit.record({
            organizationId, workspaceId, action: "DETECTION_MATCHED",
            resourceType: "DetectionRule", resourceId: rule.id,
            metadata: { matchId: matchRow.id as string, alertId: raised.alert?.id as string, suppressed: raised.suppressed },
          }).catch(() => undefined);
        }
      } catch {
        await this.prisma.detectionRule.update({
          where: { id: rule.id }, data: { evaluationFailures: ((rule.evaluationFailures as number) ?? 0) + 1 } as never,
        }).catch(() => undefined);
      }
    }
    return { matches, alertsCreated };
  }

  private toCanonical(row: Row): CanonicalTelemetryEvent {
    return {
      providerEventId: row.id as string,
      eventTime: row.eventTime instanceof Date ? row.eventTime.toISOString() : String(row.eventTime),
      source: row.source as string, sourceCategory: row.sourceCategory as string,
      eventCategory: row.eventCategory as string, eventAction: row.eventAction as string,
      assetId: row.assetId as string | undefined, identityReference: row.identityReference as string | undefined,
      severity: row.severity as CanonicalTelemetryEvent["severity"],
      classification: row.classification as CanonicalTelemetryEvent["classification"],
      attributes: (row.attributes as Record<string, unknown>) ?? {},
      schemaVersion: (row.schemaVersion as string) ?? "1.0",
    };
  }

  /** §112/§113: ATT&CK coverage from ACTIVE + tested rules only. */
  async coverage(user: RequestUser, workspaceId: string) {
    requireSocPermission(user, "VIEW_SOC");
    const rules = await this.prisma.detectionRule.findMany({ where: { workspaceId } });
    const testedRuleIds = new Set<string>();
    // A rule counts as "tested" when a TESTING-phase evaluation or a
    // recorded match exists — matches are the strongest test evidence.
    for (const rule of rules as RuleRow[]) {
      if ((rule.matchCount as number) > 0 || rule.status !== "DRAFT") testedRuleIds.add(rule.id);
    }
    return computeDetectionCoverage((rules as RuleRow[]).map((r) => ({
      id: r.id, status: r.status as string, tested: testedRuleIds.has(r.id),
      attack: (r.attackMappings as never) ?? [], dataSources: (r.dataSources as string[]) ?? [],
      lastEvaluatedAt: r.lastEvaluatedAt ? new Date(r.lastEvaluatedAt as string).toISOString() : null,
      evaluationFailures: (r.evaluationFailures as number) ?? 0,
      matchCount: (r.matchCount as number) ?? 0, falsePositiveCount: 0, triagedCount: 0,
    })));
  }

  /** §114: detection health. */
  async health(user: RequestUser, workspaceId: string) {
    requireSocPermission(user, "VIEW_SOC");
    const rules = await this.prisma.detectionRule.findMany({ where: { workspaceId } });
    const enriched = [];
    for (const rule of rules as RuleRow[]) {
      const alerts = await this.prisma.securityAlert.findMany({ where: { workspaceId, ruleId: rule.id } });
      const triage = await this.prisma.alertTriage.findMany({ where: { workspaceId } });
      const alertIds = new Set((alerts as Row[]).map((a) => a.id as string));
      const rows = (triage as Row[]).filter((t) => alertIds.has(t.alertId as string));
      enriched.push({
        id: rule.id, status: rule.status as string, tested: (rule.matchCount as number) > 0,
        attack: (rule.attackMappings as never) ?? [], dataSources: (rule.dataSources as string[]) ?? [],
        lastEvaluatedAt: rule.lastEvaluatedAt ? new Date(rule.lastEvaluatedAt as string).toISOString() : null,
        evaluationFailures: (rule.evaluationFailures as number) ?? 0,
        matchCount: (rule.matchCount as number) ?? 0,
        falsePositiveCount: rows.filter((t) => t.decision === "FALSE_POSITIVE").length,
        triagedCount: rows.length,
      });
    }
    return computeDetectionHealth(enriched, new Date());
  }
}
