import { Inject, Injectable } from "@nestjs/common";
import {
  composeGrcAnswer, parseGrcQuery, type GrcAiContextRecord,
} from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../../prisma/prisma.module";
import type { RequestUser } from "../../../common/decorators/auth.decorators";
import { requireGrcPermission } from "../permissions";
import type { AiAskInput } from "../dto/schemas";

/**
 * AI GRC assistant (Prompt 26 §88–§93), extending the Prompt 21
 * copilot's grounding discipline. Context is assembled ONLY from
 * workspace records the caller may see; the SDK composer enforces
 * citations, the certification-claim block (§90/§137) and
 * INSUFFICIENT_EVIDENCE (§92/§138). The RULE_BASED provider is the
 * live transport here (external AI providers remain NOT_CONFIGURED,
 * as in Prompt 21) and is labelled as such — never presented as a
 * model. AI mapping suggestions are advisory; the deterministic
 * mapping table remains authoritative (§91).
 */
@Injectable()
export class AiGrcService {
  constructor(@Inject(PRISMA) private readonly prisma: PrismaClientLike) {}

  private async buildContext(user: RequestUser, workspaceId: string, input: AiAskInput): Promise<GrcAiContextRecord[]> {
    const records: GrcAiContextRecord[] = [];
    if (input.controlId) {
      const control = await this.prisma.securityControl.findFirst({ where: { id: input.controlId, workspaceId } });
      if (control) {
        records.push({
          kind: "CONTROL", id: control.id, label: control.code,
          text: `${control.title}. Type ${control.controlType}/${control.implementationType}. Implementation ${control.implementationStatus}, effectiveness ${control.effectiveness}.`,
        });
        const evidence = await this.prisma.complianceEvidence.findMany({
          where: { workspaceId, controlId: control.id }, orderBy: { collectedAt: "desc" }, take: 10,
        });
        for (const ev of evidence) {
          records.push({
            kind: "EVIDENCE", id: ev.id, label: `${ev.sourceType}:${ev.sourceId}`,
            text: `Evidence from ${ev.sourceType} (${ev.sourceId}), collected ${new Date(ev.collectedAt).toISOString()}, classification ${ev.classification}, review ${ev.reviewStatus}, hash ${ev.hash}.`,
          });
        }
        const evaluation = await this.prisma.controlEvaluation.findFirst({
          where: { workspaceId, controlId: control.id }, orderBy: { evaluatedAt: "desc" },
        });
        if (evaluation) {
          records.push({
            kind: "EVIDENCE", id: evaluation.id, label: `evaluation:${control.code}`,
            text: `Latest control evaluation: ${evaluation.result} (confidence ${evaluation.confidence}) — ${evaluation.reason}`,
          });
        }
      }
    }
    if (input.requirementId) {
      const req = await this.prisma.complianceRequirement.findFirst({ where: { id: input.requirementId } });
      if (req) {
        records.push({
          kind: "REQUIREMENT", id: req.id, label: req.requirementId,
          text: `${req.requirementId} — ${req.title}. ${req.description}`,
        });
      }
    }
    if (input.riskId) {
      const risk = await this.prisma.riskRecord.findFirst({ where: { id: input.riskId, workspaceId } });
      if (risk) {
        records.push({
          kind: "RISK", id: risk.id, label: risk.title,
          text: `Risk "${risk.title}": inherent ${risk.inherentScore} (${risk.inherentBand}); residual ${risk.residualScore ?? "not assessed"} — ${risk.residualBasis} Status ${risk.status}.`,
        });
      }
    }
    // Certification facts exist ONLY as approved organizational data:
    // an ACTIVE governance policy whose title records a certification.
    // Absent that, the context deliberately contains no such record.
    const certPolicies = await this.prisma.governancePolicy.findMany({
      where: { workspaceId, status: "ACTIVE" },
    });
    for (const p of certPolicies.filter((p) => /certificat/i.test(p.title))) {
      records.push({
        kind: "CERTIFICATION_RECORD", id: p.id, label: p.title,
        text: `Approved organizational record: ${p.title} (policy version ${p.version}, status ACTIVE).`,
      });
    }
    void user;
    return records;
  }

  async ask(user: RequestUser, workspaceId: string, input: AiAskInput) {
    requireGrcPermission(user, "VIEW_GRC");
    const context = await this.buildContext(user, workspaceId, input);
    // Deterministic RULE_BASED draft: extractive summary of the context
    // (labelled honestly; a configured AI provider would draft through
    // the Prompt 21 pipeline under the same composer contract).
    const draft = context.length === 0
      ? "No workspace records were available for this question."
      : context.map((r) => `${r.label}: ${r.text}`).join("\n");
    const answer = composeGrcAnswer({
      question: input.question, draft,
      context, citedRecordIds: context.map((r) => r.id),
    });
    return {
      provider: "RULE_BASED",
      providerNote: "Deterministic grounded summary; external AI providers are NOT_CONFIGURED in this deployment (Prompt 21 discipline).",
      ...answer,
    };
  }

  /** §93: natural-language GRC search via the deterministic plan parser. */
  async search(user: RequestUser, workspaceId: string, query: string) {
    requireGrcPermission(user, "VIEW_GRC");
    const plan = parseGrcQuery(query);
    if (plan.kind === "FAILED_CONTROLS_WITH_FINDINGS") {
      const evaluations = await this.prisma.controlEvaluation.findMany({
        where: { workspaceId }, orderBy: { evaluatedAt: "desc" }, take: 1000,
      });
      const latest = new Map<string, string>();
      for (const e of evaluations) if (!latest.has(e.controlId)) latest.set(e.controlId, e.result);
      const failedIds = [...latest.entries()].filter(([, r]) => r === "FAIL").map(([id]) => id);
      const links = await this.prisma.findingControlLink.findMany({
        where: { workspaceId, controlId: { in: failedIds } },
      });
      return { plan, failedControlIds: failedIds, linkedFindingIds: links.map((l) => l.findingId) };
    }
    if (plan.kind === "STALE_EVIDENCE_CONTROLS") {
      const evidence = await this.prisma.complianceEvidence.findMany({ where: { workspaceId }, take: 1000 });
      const staleControlIds = [...new Set(evidence.filter((e) => e.status === "STALE" || e.status === "EXPIRED").map((e) => e.controlId))];
      return { plan, staleControlIds };
    }
    if (plan.kind === "EXPIRING_RISK_ACCEPTANCES") {
      const within = (plan.withinDays ?? 30) * 86_400_000;
      const now = Date.now();
      const acceptances = await this.prisma.riskAcceptance.findMany({ where: { workspaceId, status: "ACCEPTED" } });
      return {
        plan,
        expiring: acceptances.filter((a) => new Date(a.expiresAt).getTime() - now <= within && new Date(a.expiresAt).getTime() > now),
      };
    }
    return { plan, note: "Query phrasing is not supported by the deterministic GRC query grammar (§93)." };
  }
}
