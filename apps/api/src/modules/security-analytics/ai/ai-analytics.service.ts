import { Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  explainAttackPath, explainTrend, timeSeries, translateNlToDsl, countInRange, bucketForRange,
} from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { SearchService } from "../search/search.service";
import { GraphService } from "../graph/graph.service";

/**
 * AI security intelligence over analytics (§104–§109).
 *
 * Extends the copilot pattern into the lake: natural language is
 * translated DETERMINISTICALLY into the governed DSL (§108) and run
 * through the same authorized search pipeline a human uses — the AI
 * inherits tenant/RBAC/classification enforcement, never bypasses
 * it. Trend answers cite the deterministic metric values they were
 * computed from (§105); with insufficient history the answer is
 * INSUFFICIENT_DATA (§141). The AI never writes SQL (§109).
 */
@Injectable()
export class AiAnalyticsService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly search: SearchService,
    private readonly graph: GraphService,
  ) {}

  async ask(user: RequestUser, workspace: { id: string }, question: string) {
    const translated = translateNlToDsl(question);
    if ("rejected" in translated) {
      return { status: "INSUFFICIENT_EVIDENCE", answer: translated.rejected, dsl: null, citations: [] as Array<{ kind: string; ref: string }> };
    }
    const result = await this.search.search(user, workspace, { query: translated.dsl, pageSize: 10 });
    const citations = result.results.map((r) => ({ kind: r.documentType, ref: r.resourceId }));
    if (!result.results.length) {
      return {
        status: "INSUFFICIENT_EVIDENCE",
        answer: `No authorized records match (${translated.notes.join("; ")}). DSL executed: ${translated.dsl}. Nothing is inferred beyond the recorded data.`,
        dsl: translated.dsl, citations,
      };
    }
    const top = result.results.slice(0, 5).map((r) => `- [${r.documentType}] ${r.title} (${r.severity ?? "n/a"}, risk ${r.riskScore ?? "n/a"})`).join("\n");
    return {
      status: "OK",
      answer: `Found ${result.total} matching record(s) for: ${translated.notes.join("; ")}.\nDSL executed: ${translated.dsl}\nTop matches:\n${top}`,
      dsl: translated.dsl, citations,
    };
  }

  /** "How much did critical exposure increase?" — deterministic numbers only (§140). */
  async trend(user: RequestUser, workspace: { id: string }, question: string) {
    const now = new Date();
    const events = await this.prisma.securityAnalyticsEvent.findMany({
      where: { workspaceId: workspace.id }, orderBy: { eventTime: "asc" }, take: 10_000,
    });
    const wantsCritical = /critical/i.test(question);
    const wantsKev = /kev/i.test(question);
    const metric = wantsKev ? "KEV detections" : wantsCritical ? "Critical findings created" : "Findings created";
    const relevant = events.filter((e) => {
      if (wantsKev) return e.eventType === "KEV_DETECTED";
      if (wantsCritical) return e.eventType === "FINDING_CREATED" && e.severity === "CRITICAL";
      return e.eventType === "FINDING_CREATED";
    });
    const from = new Date(now.getTime() - 30 * 86_400_000);
    const prevFrom = new Date(now.getTime() - 60 * 86_400_000);
    const series = timeSeries(relevant, (e) => e.eventTime, bucketForRange(from, now), { from, to: now });
    const current = countInRange(relevant, (e) => e.eventTime, from, now);
    const previous = countInRange(relevant, (e) => e.eventTime, prevFrom, from);
    const explained = explainTrend({
      metric, seriesPoints: series.filter((p) => p.count > 0).length > 0 ? series.length : relevant.length,
      current: relevant.length ? current : null, previous: relevant.length ? previous : null,
      rangeLabel: "the last 30 days vs the prior 30 days",
    });
    return { ...explained, dsl: null, citations: [...explained.citations, ...relevant.slice(0, 5).map((e) => ({ kind: "SECURITY_EVENT", ref: e.eventId }))] };
  }

  /** §107: explain a stored attack-path candidate from its evidence. */
  async explainPath(user: RequestUser, workspace: { id: string }, pathId: string) {
    void user;
    const path = await this.graph.getAttackPath(workspace.id, pathId);
    if (!path) throw new NotFoundException("Attack path candidate not found");
    return {
      status: "OK",
      answer: explainAttackPath({
        title: path.title, score: path.score, confidence: path.confidence,
        nodes: (path.nodes as Array<{ kind: string; label: string }>), edges: (path.edges as Array<{ evidenceType: string; evidenceId: string }>),
      }),
      citations: [{ kind: "ATTACK_PATH", ref: path.id }],
    };
  }
}
