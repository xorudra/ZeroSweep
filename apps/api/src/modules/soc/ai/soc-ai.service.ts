import { Inject, Injectable } from "@nestjs/common";
import {
  answerAttributionQuestion, composeIncidentSummary, translateSocNaturalQuery,
  type SocIncidentFacts,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireSocPermission } from "../permissions";
import { IncidentService } from "../incidents/incident.service";
import type { Row } from "../helpers";

/**
 * AI SOC copilot (Prompt 28 §95–§101). Deterministic, grounded
 * composition over the workspace's own SOC records (the P21/P27
 * discipline): answers cite record ids, missing evidence yields
 * INSUFFICIENT_EVIDENCE, attribution is refused without reliable
 * recorded intelligence (§99/§151), and the copilot can only
 * RECOMMEND predefined response actions / playbooks — execution
 * lives behind the response engine's approval policy (§96/§152).
 */
@Injectable()
export class SocAiService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly incidents: IncidentService,
  ) {}

  private async buildFacts(user: RequestUser, workspaceId: string, incidentId?: string, alertId?: string): Promise<SocIncidentFacts> {
    const facts: SocIncidentFacts = {
      incident: null, alerts: [], events: [], assets: [], identities: [],
      indicators: [], timeline: [], actionsTaken: [],
    };
    if (incidentId) {
      const detail = await this.incidents.getIncidentDetail(user, workspaceId, incidentId).catch(() => null);
      if (detail) {
        const incident = detail.incident as Row;
        facts.incident = {
          id: incident.id as string, title: incident.title as string, status: incident.status as string,
          severity: incident.severity as string, priority: incident.priority as string,
        };
        facts.timeline = (detail.timeline as Row[]).map((t) => ({
          entryType: t.entryType as string, summary: t.summary as string,
          createdAt: new Date(t.createdAt as string).toISOString(),
        }));
        facts.actionsTaken = (detail.responseActions as Row[]).map((a) => ({
          actionKey: a.actionKey as string, status: a.status as string,
        }));
        const alertIds = (detail.links as Row[]).filter((l) => l.resourceType === "ALERT").map((l) => l.resourceId as string);
        for (const id of alertIds) {
          const alert = await this.prisma.securityAlert.findFirst({ where: { id, workspaceId } });
          if (alert) facts.alerts.push({ id, title: (alert as Row).title as string, severity: (alert as Row).severity as string, status: (alert as Row).status as string });
        }
        const indicatorIds = (detail.links as Row[]).filter((l) => l.resourceType === "INDICATOR").map((l) => l.resourceId as string);
        for (const id of indicatorIds) {
          const indicator = await this.prisma.threatIndicator.findFirst({ where: { id, workspaceId } });
          if (indicator) {
            const observations = await this.prisma.indicatorObservation.findMany({ where: { workspaceId, indicatorId: id } });
            const sourceName = ((observations as Row[])[0]?.detail as Row)?.sourceName as string ?? "recorded source";
            facts.indicators.push({
              id, type: (indicator as Row).type as string, valueNormalized: (indicator as Row).valueNormalized as string,
              confidence: (indicator as Row).confidence as number, sourceName,
            });
          }
        }
      }
    }
    if (alertId) {
      const alert = await this.prisma.securityAlert.findFirst({ where: { id: alertId, workspaceId } });
      if (alert) {
        facts.alerts.push({ id: alertId, title: (alert as Row).title as string, severity: (alert as Row).severity as string, status: (alert as Row).status as string });
        if ((alert as Row).identityReference) facts.identities.push((alert as Row).identityReference as string);
        if ((alert as Row).indicatorId) {
          const indicator = await this.prisma.threatIndicator.findFirst({ where: { id: (alert as Row).indicatorId as string, workspaceId } });
          if (indicator) {
            facts.indicators.push({
              id: (indicator as Row).id as string, type: (indicator as Row).type as string,
              valueNormalized: (indicator as Row).valueNormalized as string,
              confidence: (indicator as Row).confidence as number, sourceName: "workspace intel store",
            });
          }
        }
        const matches = await this.prisma.detectionMatch.findMany({ where: { workspaceId, alertId } });
        const eventIds = [...new Set((matches as Row[]).flatMap((m) => (m.eventIds as string[]) ?? []))];
        for (const eventId of eventIds.slice(0, 10)) {
          const event = await this.prisma.securityTelemetryEvent.findFirst({ where: { id: eventId, workspaceId } });
          if (event) facts.events.push({ id: eventId, eventAction: (event as Row).eventAction as string, eventTime: new Date((event as Row).eventTime as string).toISOString() });
        }
      }
    }
    return facts;
  }

  async ask(user: RequestUser, workspaceId: string, body: { question: string; incidentId?: string; alertId?: string }) {
    requireSocPermission(user, "VIEW_SOC");
    const question = body.question.toLowerCase();
    const facts = await this.buildFacts(user, workspaceId, body.incidentId, body.alertId);
    // §151: attribution questions take the guarded path, always.
    if (/who attacked|who is behind|attribut|which country|which group|apt/.test(question)) {
      return answerAttributionQuestion(facts);
    }
    // §101: natural-language SOC search.
    const translated = translateSocNaturalQuery(body.question);
    if (translated && !body.incidentId && !body.alertId) {
      return {
        status: "OK" as const,
        summary: `Translated to a governed SOC query (no raw SQL is generated, §101).`,
        sections: { Query: [`kind=${translated.kind}`, ...Object.entries(translated.filters).map(([k, v]) => `${k}=${v}`)] },
        citations: [],
        recommendedActions: [],
        attribution: { claimed: false as const, note: "No attribution is made." },
        query: translated,
      };
    }
    const answer = composeIncidentSummary(facts);
    // §95/§96: recommend — never execute — predefined playbooks/actions.
    if (facts.alerts.some((a) => /credential|session|api.?key/i.test(a.title))) {
      answer.recommendedPlaybookKey = "suspected-credential-compromise";
      answer.recommendedActions = [{ actionKey: "REVOKE_DSRCLONE_SESSION", note: "Recommendation only — execution requires the response engine's approval policy (§96)." }];
    } else if (facts.indicators.length > 0) {
      answer.recommendedPlaybookKey = "malicious-indicator-match";
    }
    return answer;
  }
}
