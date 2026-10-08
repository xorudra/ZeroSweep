import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  computeIndicatorConfidence, indicatorIsActiveForDetection, normalizeIndicatorValue,
  parseStixBundle, type IndicatorType,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import { AuditService } from "../../audit/audit.service";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireSocPermission } from "../permissions";
import { AlertService } from "../alerts/alert.service";
import { socAlertFingerprint } from "@dsrclone/security-sdk";
import type { Row } from "../helpers";

interface IndicatorInput {
  type: IndicatorType; value: string; confidence?: number; severity?: string;
  validUntil?: string; tags?: string[]; references?: string[]; stixId?: string;
}

/**
 * Threat intelligence (Prompt 28 §54–§69). Indicators are tenant
 * data: a private indicator in workspace A is invisible to workspace
 * B (§155). Every indicator keeps per-source provenance (§62);
 * confidence is the deterministic SDK policy (§63); expiry is
 * honored at match time (§66). Internal data is never submitted to
 * external providers (§68) — there is no outbound lookup path here
 * at all. Live feed transports are NOT wired: sync attempts report
 * NOT_CONFIGURED honestly; recorded fixture/manual imports are the
 * ingestion path.
 */
@Injectable()
export class IntelService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly alerts: AlertService,
  ) {}

  async createSource(user: RequestUser, workspaceId: string, body: {
    name: string; type: string; trustLevel?: number; authenticationReference?: string; syncFrequencyMinutes?: number;
  }) {
    requireSocPermission(user, "MANAGE_THREAT_INTEL");
    const source = await this.prisma.threatIntelSource.create({
      data: {
        organizationId: user.organizationId, workspaceId, name: body.name, type: body.type,
        trustLevel: body.trustLevel ?? 50, authenticationReference: body.authenticationReference,
        syncFrequencyMinutes: body.syncFrequencyMinutes, transportStatus: "NOT_CONFIGURED",
      },
    });
    return source;
  }

  async listSources(user: RequestUser, workspaceId: string) {
    requireSocPermission(user, "VIEW_THREAT_INTEL");
    const items = await this.prisma.threatIntelSource.findMany({ where: { workspaceId }, orderBy: { name: "asc" } });
    return { items, total: items.length };
  }

  async getSource(user: RequestUser, workspaceId: string, sourceId: string): Promise<Row> {
    requireSocPermission(user, "VIEW_THREAT_INTEL");
    const source = await this.prisma.threatIntelSource.findFirst({ where: { id: sourceId, workspaceId } });
    if (!source) throw new NotFoundException("Threat intel source not found in this workspace");
    return source as Row;
  }

  /** §59/§60: a live sync is attempted only through a wired
   *  transport. None exists in this environment, so the sync records
   *  NOT_CONFIGURED and imports nothing — never a fabricated feed. */
  async syncSource(user: RequestUser, workspaceId: string, sourceId: string) {
    requireSocPermission(user, "MANAGE_THREAT_INTEL");
    const source = await this.getSource(user, workspaceId, sourceId);
    const sync = await this.prisma.threatIntelFeedSync.create({
      data: {
        sourceId, workspaceId, status: "NOT_CONFIGURED", mode: "LIVE",
        errors: ["Live feed transport is not wired for this source; use a recorded fixture/manual import."] as never,
        completedAt: new Date(),
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "THREAT_INTEL_SYNCED", resourceType: "ThreatIntelSource", resourceId: sourceId,
      metadata: { status: "NOT_CONFIGURED", source: source.name },
    });
    return sync;
  }

  /** Import indicators (fixture STIX bundle or plain list) under one
   *  source, with dedupe + provenance (§61/§62). Hostile-input caps
   *  are enforced by the SDK parser and the DTO. */
  async importIndicators(user: RequestUser, workspaceId: string, sourceId: string, body: {
    format: "STIX" | "INDICATORS"; bundle?: unknown; indicators?: IndicatorInput[];
  }) {
    requireSocPermission(user, "MANAGE_THREAT_INTEL");
    const source = await this.getSource(user, workspaceId, sourceId);
    let inputs: IndicatorInput[] = [];
    let parseErrors: string[] = [];
    if (body.format === "STIX") {
      const parsed = parseStixBundle(body.bundle);
      parseErrors = parsed.errors;
      inputs = parsed.indicators.map((i) => ({
        type: i.type, value: i.valueNormalized, confidence: i.confidence,
        validUntil: i.validUntil, tags: i.labels, references: i.externalReferences, stixId: i.stixId,
      }));
    } else {
      inputs = body.indicators ?? [];
    }
    let created = 0;
    let updated = 0;
    for (const input of inputs) {
      const result = await this.upsertIndicator(user, workspaceId, source, input);
      if (result === "created") created++;
      else if (result === "updated") updated++;
    }
    const sync = await this.prisma.threatIntelFeedSync.create({
      data: {
        sourceId, workspaceId, status: "COMPLETED",
        mode: source.type === "FIXTURE" ? "FIXTURE_IMPORT" : "MANUAL_IMPORT",
        indicatorsIn: inputs.length, created, updated, errors: parseErrors as never, completedAt: new Date(),
      },
    });
    await this.audit.record({
      actorId: user.id, organizationId: user.organizationId, workspaceId,
      action: "THREAT_INTEL_SYNCED", resourceType: "ThreatIntelSource", resourceId: sourceId,
      metadata: { format: body.format, indicatorsIn: inputs.length, created, updated },
    });
    return { sync, created, updated, indicatorsIn: inputs.length, parseErrors };
  }

  async addIndicator(user: RequestUser, workspaceId: string, body: IndicatorInput & { sourceId: string }) {
    requireSocPermission(user, "MANAGE_THREAT_INTEL");
    const source = await this.getSource(user, workspaceId, body.sourceId);
    const outcome = await this.upsertIndicator(user, workspaceId, source, body);
    const indicator = await this.prisma.threatIndicator.findFirst({
      where: { workspaceId, type: body.type, valueNormalized: normalizeIndicatorValue(body.type, body.value) ?? body.value },
    });
    return { outcome, indicator };
  }

  private async upsertIndicator(user: RequestUser, workspaceId: string, source: Row, input: IndicatorInput): Promise<"created" | "updated" | "rejected"> {
    const valueNormalized = normalizeIndicatorValue(input.type, input.value);
    if (!valueNormalized) return "rejected";
    const now = new Date();
    const existing = await this.prisma.threatIndicator.findFirst({
      where: { workspaceId, type: input.type, valueNormalized },
    });
    const observations = existing
      ? await this.prisma.indicatorObservation.findMany({ where: { workspaceId, indicatorId: existing.id as string } })
      : [];
    const sourceIds = new Set((observations as Row[]).map((o) => o.sourceId as string));
    sourceIds.add(source.id as string);
    const confidence = computeIndicatorConfidence({
      sourceTrust: (source.trustLevel as number) ?? 50,
      observedAt: now, now, independentSourceCount: sourceIds.size,
      analystConfidence: input.confidence,
    });
    let indicatorId: string;
    let outcome: "created" | "updated";
    if (existing) {
      indicatorId = existing.id as string;
      outcome = "updated";
      await this.prisma.threatIndicator.update({
        where: { id: indicatorId },
        data: {
          confidence, lastSeen: now,
          severity: input.severity ?? (existing.severity as string),
          validUntil: input.validUntil ? new Date(input.validUntil) : (existing.validUntil as Date | undefined),
          tags: input.tags ?? (existing.tags as never),
          references: input.references ?? (existing.references as never),
        } as never,
      });
    } else {
      const created = await this.prisma.threatIndicator.create({
        data: {
          organizationId: user.organizationId, workspaceId, type: input.type, valueNormalized,
          confidence, severity: input.severity ?? "MEDIUM", status: "ACTIVE",
          firstSeen: now, lastSeen: now,
          validUntil: input.validUntil ? new Date(input.validUntil) : undefined,
          tags: (input.tags ?? []) as never, references: (input.references ?? []) as never,
        },
      });
      indicatorId = created.id as string;
      outcome = "created";
    }
    await this.prisma.indicatorObservation.create({
      data: {
        indicatorId, sourceId: source.id as string, workspaceId, observedAt: now,
        confidence: input.confidence, stixId: input.stixId,
        detail: { sourceName: source.name, sourceTrust: source.trustLevel } as never,
      },
    });
    return outcome;
  }

  /** §67: threat-intel search — strictly workspace-scoped (§155). */
  async searchIndicators(user: RequestUser, workspaceId: string, filters: {
    q?: string; type?: string; status?: string; minConfidence?: number; limit?: number;
  }) {
    requireSocPermission(user, "VIEW_THREAT_INTEL");
    let items = await this.prisma.threatIndicator.findMany({
      where: {
        workspaceId,
        ...(filters.type ? { type: filters.type } : {}),
        ...(filters.status ? { status: filters.status } : {}),
      },
      orderBy: { lastSeen: "desc" }, take: 500,
    }) as Row[];
    if (filters.q) {
      const q = filters.q.toLowerCase();
      items = items.filter((i) => (i.valueNormalized as string).toLowerCase().includes(q));
    }
    if (filters.minConfidence !== undefined) {
      items = items.filter((i) => (i.confidence as number) >= filters.minConfidence!);
    }
    const enriched = [];
    for (const indicator of items.slice(0, filters.limit ?? 100)) {
      const observations = await this.prisma.indicatorObservation.findMany({
        where: { workspaceId, indicatorId: indicator.id as string },
      });
      const sources = [...new Set((observations as Row[]).map((o) => (o.detail as Row)?.sourceName as string).filter(Boolean))];
      enriched.push({ ...indicator, provenance: { sources, observationCount: (observations as Row[]).length } });
    }
    return { items: enriched, total: enriched.length };
  }

  /**
   * §64/§65: match one stored telemetry event against the workspace
   * indicator store. Candidate values come from the event itself:
   * source IP attribute, identity, URL/domain attributes and file
   * hashes. A match records provenance + the indicator confidence at
   * match time; low confidence enriches only (§69/§140).
   */
  async matchEvent(organizationId: string, workspaceId: string, eventRow: Row): Promise<{ matches: number; alertIds: string[] }> {
    const attributes = (eventRow.attributes as Record<string, unknown>) ?? {};
    const candidates: Array<{ type: IndicatorType; value: string }> = [];
    const push = (type: IndicatorType, value: unknown) => {
      if (typeof value === "string" && value) {
        const normalized = normalizeIndicatorValue(type, value);
        if (normalized) candidates.push({ type, value: normalized });
      }
    };
    push("IP", attributes.sourceIp);
    push("DOMAIN", attributes.domain);
    push("URL", attributes.url);
    push("FILE_HASH", attributes.fileHash);
    push("EMAIL_DOMAIN", typeof attributes.email === "string" ? attributes.email.split("@")[1] : undefined);
    if (candidates.length === 0) return { matches: 0, alertIds: [] };

    let matches = 0;
    const alertIds: string[] = [];
    const now = new Date();
    for (const candidate of candidates) {
      const indicator = await this.prisma.threatIndicator.findFirst({
        where: { workspaceId, type: candidate.type, valueNormalized: candidate.value },
      }) as Row | null;
      if (!indicator) continue;
      const active = indicatorIsActiveForDetection({
        status: indicator.status as string, validUntil: indicator.validUntil as Date | undefined, now,
      });
      const observations = await this.prisma.indicatorObservation.findMany({
        where: { workspaceId, indicatorId: indicator.id as string },
      });
      const sourceNames = [...new Set((observations as Row[]).map((o) => (o.detail as Row)?.sourceName as string).filter(Boolean))];
      const match = await this.prisma.indicatorMatch.create({
        data: {
          organizationId, workspaceId, indicatorId: indicator.id as string,
          telemetryEventId: eventRow.id as string, assetId: eventRow.assetId as string | undefined,
          identityReference: eventRow.identityReference as string | undefined,
          confidence: indicator.confidence as number,
          context: {
            provenance: sourceNames, indicatorStatus: indicator.status,
            detectionActive: active, eventAction: eventRow.eventAction,
          } as never,
        },
      });
      matches++;
      await this.audit.record({
        organizationId, workspaceId, action: "INDICATOR_MATCHED",
        resourceType: "ThreatIndicator", resourceId: indicator.id as string,
        metadata: { matchId: match.id as string, confidence: indicator.confidence, detectionActive: active },
      }).catch(() => undefined);
      // §69: only an ACTIVE indicator with meaningful confidence
      // raises an alert, and the alert cites the provenance — the
      // match is context, never an automatic malicious verdict.
      if (active && (indicator.confidence as number) >= 40) {
        const fingerprint = socAlertFingerprint({
          ruleId: "indicator-match", ruleVersion: 1, indicatorId: indicator.id as string,
          assetId: eventRow.assetId as string | undefined, identityReference: eventRow.identityReference as string | undefined,
        });
        const raised = await this.alerts.raiseAlert({
          organizationId, workspaceId, fingerprint,
          title: `Indicator match: ${indicator.type} ${indicator.valueNormalized}`,
          description: `Telemetry event ${eventRow.eventAction} matched indicator from ${sourceNames.join(", ") || "recorded source"} (confidence ${indicator.confidence}). Provenance is recorded on the match; this is enrichment context, not an attribution (§69).`,
          severity: indicator.severity as string, source: "INDICATOR_MATCH",
          indicatorId: indicator.id as string, assetId: eventRow.assetId as string | undefined,
          identityReference: eventRow.identityReference as string | undefined,
          threatIntelConfidence: indicator.confidence as number,
          confidence: (indicator.confidence as number) >= 70 ? "HIGH" : "MEDIUM",
        });
        if (raised.alert) alertIds.push(raised.alert.id as string);
      }
    }
    return { matches, alertIds };
  }

  async listMatches(user: RequestUser, workspaceId: string, filters: { indicatorId?: string; limit?: number }) {
    requireSocPermission(user, "VIEW_THREAT_INTEL");
    const items = await this.prisma.indicatorMatch.findMany({
      where: { workspaceId, ...(filters.indicatorId ? { indicatorId: filters.indicatorId } : {}) },
      orderBy: { matchedAt: "desc" }, take: Math.min(filters.limit ?? 100, 500),
    });
    return { items, total: items.length };
  }
}
