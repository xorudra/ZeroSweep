import { BadRequestException, Inject, Injectable } from "@nestjs/common";
import { translateRemediationQuery, type RemediationQueryPlan } from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { CaseStateService } from "./case-state.service";
import { RemediationCasesService } from "./cases.service";
import { RemediationPlansService } from "./plans.service";
import { requireRemediationPermission } from "./permissions";

const MARK_FIXED = /\b(mark|set|declare|close|verify|approve)\b[^.]*\b(fixed|closed|verified|resolved)\b/i;

/**
 * Remediation AI assistance (Prompt 31 §116) + deterministic NL search
 * (§117). The copilot works from the CASE's own normalized data. It may
 * summarize, explain prioritization, draft plans/tickets from recorded
 * intelligence, explain a verification failure and suggest campaign
 * groupings. It CANNOT mark anything fixed/verified/closed (§151/§157)
 * and CANNOT invent a patch or fixed version — drafts pass through the
 * same trusted-intelligence check as human plans (§34/§35).
 */
@Injectable()
export class RemediationAiService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly state: CaseStateService,
    private readonly cases: RemediationCasesService,
    private readonly plans: RemediationPlansService,
  ) {}

  async assist(user: RequestUser, workspaceId: string, caseId: string, input: { task: string; instruction?: string }) {
    requireRemediationPermission(user, "VIEW_REMEDIATION");
    const kase = await this.state.getCase(workspaceId, caseId);
    const finding = await this.state.getFinding(workspaceId, kase.findingId);
    const instruction = input.instruction ?? "";
    if (MARK_FIXED.test(instruction) || MARK_FIXED.test(input.task)) {
      throw new BadRequestException(
        "AI cannot mark a finding fixed, verified or closed (§116/§157) — those states come only from the verification engine or an approved exception",
      );
    }
    const trusted = await this.plans.trustedFixedVersions(workspaceId, kase.findingId);
    const base = {
      caseId, status: kase.status, priority: kase.priority,
      executed: false,
      groundedOn: { findingId: finding.id, severity: finding.severity, cve: finding.cve, kevListed: finding.kevListed },
    };
    switch (input.task) {
      case "SUMMARIZE_CASE": {
        const history = await this.prisma.remediationStatusHistory.findMany({ where: { caseId }, orderBy: { createdAt: "asc" } });
        return {
          ...base,
          summary: `${finding.title} — ${finding.severity}${finding.cve ? ` (${finding.cve})` : ""}. Case status ${kase.status}, priority ${kase.priority ?? "unset"}, due ${kase.dueAt?.toISOString() ?? "no SLA date"}. ${history.length} recorded state transitions; latest: ${history.at(-1)?.toStatus ?? "NEW"}.`,
        };
      }
      case "EXPLAIN_PRIORITY": {
        const factors = (finding.riskFactors as Array<{ factor?: string; value?: unknown; contribution?: number }> | null) ?? [];
        return {
          ...base,
          explanation: factors.length
            ? factors.map((f) => `${f.factor ?? "factor"}: ${JSON.stringify(f.value)} (contribution ${f.contribution ?? "n/a"})`).join("; ")
            : "no recorded risk factors — priority follows the recorded severity/priority inputs only; nothing is inferred",
          riskScore: finding.riskScore, riskBand: finding.riskBand,
        };
      }
      case "DRAFT_PLAN": {
        if (trusted.length === 0) {
          return {
            ...base, draft: null,
            refusal: "no trusted patch intelligence records a fixed version for this finding — a plan draft would have to invent one, which is forbidden (§35)",
          };
        }
        return {
          ...base,
          draft: {
            summary: `Upgrade ${finding.componentPurl ?? finding.title} to fixed version ${trusted[0]} per recorded patch intelligence`,
            recommendedAction: "DEPENDENCY_UPDATE",
            fixedVersion: trusted[0], source: "AI_DRAFT",
            note: "draft only — a human with MANAGE_REMEDIATION_PLAN approves it through the plan workflow",
          },
        };
      }
      case "EXPLAIN_VERIFICATION_FAILURE": {
        const job = await this.prisma.remediationVerificationJob.findFirst({
          where: { caseId }, orderBy: { createdAt: "desc" },
        });
        if (!job) return { ...base, explanation: "no verification job exists for this case yet" };
        const result = job.result as { outcome?: string; reason?: string } | null;
        return {
          ...base,
          explanation: `latest verification (${job.method}) outcome: ${result?.outcome ?? job.status}. ${result?.reason ?? ""}`.trim(),
        };
      }
      case "SUGGEST_CAMPAIGN": {
        return {
          ...base,
          suggestion: finding.cve
            ? { scope: { cve: finding.cve }, note: "group every case for this CVE into one campaign; membership is collected by the campaign service from real findings" }
            : finding.componentPurl
              ? { scope: { componentPurl: finding.componentPurl }, note: "group by the vulnerable component across repositories and assets" }
              : null,
        };
      }
      default:
        throw new BadRequestException(`unknown remediation AI task ${input.task} — supported: SUMMARIZE_CASE, EXPLAIN_PRIORITY, DRAFT_PLAN, EXPLAIN_VERIFICATION_FAILURE, SUGGEST_CAMPAIGN`);
    }
  }

  /** §117: natural-language search over the deterministic query layer.
   *  The SDK translates a CLOSED set of question shapes into a typed
   *  plan; unsupported phrasing is refused, never guessed. */
  async naturalLanguageSearch(user: RequestUser, workspaceId: string, query: string) {
    requireRemediationPermission(user, "VIEW_REMEDIATION");
    const plan: RemediationQueryPlan | null = translateRemediationQuery(query);
    if (!plan) {
      throw new BadRequestException("query not understood by the deterministic remediation query layer (§117) — use the structured filters instead");
    }
    const now = Date.now();
    switch (plan.kind) {
      case "OVERDUE_KEV": {
        const queue = await this.cases.listQueue(workspaceId, { kev: true, pageSize: 200 });
        const items = queue.items.filter((i) => i.dueAt != null && i.dueAt.getTime() < now);
        return { plan, items, total: items.length };
      }
      case "OVERDUE_ALL": {
        const queue = await this.cases.listQueue(workspaceId, { pageSize: 200 });
        const items = queue.items.filter((i) => i.dueAt != null && i.dueAt.getTime() < now);
        return { plan, items, total: items.length };
      }
      case "WAITING_VERIFICATION": {
        const queue = await this.cases.listQueue(workspaceId, { status: "VERIFICATION_PENDING", pageSize: 200 });
        return { plan, items: queue.items, total: queue.items.length };
      }
      case "FIX_CLAIMED_UNVERIFIED": {
        const queue = await this.cases.listQueue(workspaceId, { status: "FIX_CLAIMED", pageSize: 200 });
        return { plan, items: queue.items, total: queue.items.length };
      }
      case "SLA_BREACHED": {
        const breached = await this.prisma.remediationSlaSnapshot.findMany({
          where: { workspaceId, state: "BREACHED" }, take: 500,
        });
        const breachedIds = new Set(breached.map((s) => s.caseId));
        const queue = await this.cases.listQueue(workspaceId, { pageSize: 200 });
        const items = queue.items.filter((i) => breachedIds.has(i.id));
        return { plan, items, total: items.length };
      }
      case "REGRESSIONS_SINCE": {
        const since = new Date(now - plan.days * 86400_000);
        const events = await this.prisma.remediationRegressionEvent.findMany({
          where: { workspaceId, detectedAt: { gte: since } }, orderBy: { detectedAt: "desc" }, take: 200,
        });
        return { plan, items: events, total: events.length };
      }
      case "TEAM_BACKLOG": {
        const queue = await this.cases.listQueue(workspaceId, {
          ...(plan.priority ? { priority: plan.priority } : {}), pageSize: 200,
        });
        const byTeam: Record<string, number> = {};
        for (const item of queue.items) {
          const key = item.teamId ?? item.ownerId ?? "unassigned";
          byTeam[key] = (byTeam[key] ?? 0) + 1;
        }
        return { plan, items: queue.items, total: queue.items.length, byTeam };
      }
      default:
        throw new BadRequestException("query plan not supported");
    }
  }
}
