import { BadRequestException, Inject, Injectable, NotFoundException } from "@nestjs/common";
import {
  AI_SAFE_DEFAULT_PROFILE, AI_TOOL_CATALOG, classifyScanProfile, evaluateAiToolCall,
  type AiToolDefinition,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import { AuditService } from "../audit/audit.service";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { aiPermissionsHeld, requireAiPermission } from "./permissions";
import { AiContextService } from "./ai-context.service";

export interface AiToolExecutionResult {
  tool: string;
  verdict: "ALLOWED" | "BLOCKED";
  code?: string;
  reason?: string;
  /** The AI never executes actions: action-category tools produce
   *  governed proposals for the owning workflow (§33/§34). */
  executed: false;
  result?: unknown;
  summary: string;
}

const PROPOSAL_ACTION_BY_TOOL: Record<string, string> = {
  createScanDraft: "CREATE_SCAN_DRAFT",
  createRemediationTicket: "CREATE_REMEDIATION_TICKET",
  requestVerification: "REQUEST_RETEST",
  generateReportDraft: "CREATE_REPORT_DRAFT",
  createInvestigationCase: "CREATE_INVESTIGATION_CASE",
  scheduleApprovedScan: "SCHEDULE_APPROVED_SCAN",
};

/**
 * AiSecurityToolGateway (Prompt 36 §27–§35). Every AI tool call —
 * from the copilot, an agent or a workflow — passes the SDK gate
 * (catalog membership, permission, authorization snapshot, human
 * approval, rate limit) and is then executed ONLY against governed,
 * workspace-scoped data functions. There is no shell, SQL, cloud,
 * Kubernetes, device or scanner surface behind this gateway (§26):
 * unknown names are refused with the reason recorded (§108–§113).
 * Tool arguments are never written to logs/traces (§132) — only the
 * tool name, verdict and arg KEY names.
 */
@Injectable()
export class AiGatewayService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly audit: AuditService,
    private readonly contexts: AiContextService,
  ) {}

  catalog(user: RequestUser): AiToolDefinition[] {
    requireAiPermission(user, "USE_AI_COPILOT");
    return AI_TOOL_CATALOG;
  }

  private async callsThisHour(workspaceId: string, userId: string, toolName: string): Promise<number> {
    const hourAgo = new Date(Date.now() - 3600000);
    const traces = await this.prisma.aiSecurityTrace.findMany({
      where: { workspaceId, userId, createdAt: { gte: hourAgo } }, take: 500,
    });
    let n = 0;
    for (const t of traces as Record<string, unknown>[]) {
      const calls = (t.toolCalls ?? []) as { tool: string }[];
      for (const c of calls) if (c.tool === toolName) n += 1;
    }
    return n;
  }

  async callTool(user: RequestUser, workspaceId: string, name: string, args: Record<string, unknown> = {}, opts: {
    hasApproval?: boolean;
    authorizationValid?: boolean;
    workflowId?: string;
    skipTrace?: boolean;
  } = {}): Promise<AiToolExecutionResult> {
    requireAiPermission(user, "USE_AI_COPILOT");
    const permissions = aiPermissionsHeld(user);
    const calls = await this.callsThisHour(workspaceId, user.id, name);
    const verdict = evaluateAiToolCall(name, {
      userPermissions: permissions,
      hasApproval: opts.hasApproval ?? false,
      authorizationValid: opts.authorizationValid ?? false,
      callsThisHour: calls,
    });
    const finish = async (out: AiToolExecutionResult): Promise<AiToolExecutionResult> => {
      await this.audit.record({
        actorId: user.id, organizationId: user.organizationId, workspaceId,
        action: "AI_TOOL_CALLED", resourceType: "AiTool", resourceId: opts.workflowId,
        metadata: { tool: name, verdict: out.verdict, code: out.code ?? null, argKeys: Object.keys(args) },
      });
      if (!opts.skipTrace) {
        await this.prisma.aiSecurityTrace.create({
          data: {
            workspaceId, userId: user.id, workflowId: opts.workflowId ?? null, taskType: "TOOL_GATEWAY",
            requestMetadata: { tool: name, argKeys: Object.keys(args) },
            toolCalls: [{ tool: name, verdict: out.verdict, code: out.code ?? null }],
            policyDecisions: [{ tool: name, verdict: out.verdict, reason: out.reason ?? "allowed" }],
            timings: {},
          },
        });
      }
      return out;
    };

    if (!verdict.allowed) {
      return finish({ tool: name, verdict: "BLOCKED", code: verdict.code, reason: verdict.reason, executed: false, summary: `blocked: ${verdict.reason}` });
    }
    const toolDef = verdict.tool;
    try {
      const result = await this.execute(user, workspaceId, toolDef.name, args);
      return finish({ tool: name, verdict: "ALLOWED", executed: false, result, summary: `${toolDef.name} completed (${toolDef.category})` });
    } catch (err) {
      if (err instanceof NotFoundException || err instanceof BadRequestException) throw err;
      return finish({ tool: name, verdict: "BLOCKED", code: "EXECUTION_ERROR", reason: (err as Error).message, executed: false, summary: `tool error: ${(err as Error).message}` });
    }
  }

  /** Governed implementations. All reads are workspace-scoped at the
   *  data layer; cross-tenant ids behave as nonexistent (§12/§105). */
  private async execute(user: RequestUser, workspaceId: string, name: string, args: Record<string, unknown>): Promise<unknown> {
    const str = (k: string) => (typeof args[k] === "string" ? (args[k] as string) : undefined);
    switch (name) {
      case "getFinding": {
        const input = await this.contexts.loadFindingInput(workspaceId, str("findingId") ?? "");
        return { finding: { id: input.id, title: input.title, severity: input.severity, status: input.lifecycleStatus ?? input.status, cve: input.cve, cwe: input.cwe, riskScore: input.riskScore, verificationStatus: input.verificationStatus } };
      }
      case "searchFindings": {
        const rows = await this.prisma.finding.findMany({ where: { workspaceId }, orderBy: { riskScore: "desc" }, take: 200 });
        const limit = Math.min(Number(args.limit ?? 10) || 10, 50);
        return {
          findings: (rows as Record<string, unknown>[])
            .filter((r) => (!str("severity") || r.severity === str("severity")) && (!str("domain") || r.sourceDomain === str("domain")) && (!args.kevOnly || r.kevListed === true))
            .slice(0, limit)
            .map((r) => ({ id: r.id, title: r.title, severity: r.severity, cve: r.cve ?? null, riskScore: r.riskScore ?? null })),
        };
      }
      case "getAsset": {
        const asset = await this.prisma.asset.findFirst({ where: { id: str("assetId") ?? "", workspaceId } });
        if (!asset) throw new NotFoundException("asset not found in this workspace");
        const findingCount = await this.prisma.finding.count({ where: { workspaceId, assetId: asset.id } });
        return { asset: { id: asset.id, host: asset.host, type: asset.type, criticality: asset.criticality, scopeStatus: asset.scopeStatus }, findingCount };
      }
      case "searchAssets": {
        const rows = await this.prisma.asset.findMany({ where: { workspaceId }, take: 200 });
        const q = (str("query") ?? "").toLowerCase();
        const limit = Math.min(Number(args.limit ?? 10) || 10, 50);
        return {
          assets: (rows as Record<string, unknown>[])
            .filter((r) => !q || String(r.host ?? "").toLowerCase().includes(q))
            .slice(0, limit)
            .map((r) => ({ id: r.id, host: r.host, type: r.type, criticality: r.criticality })),
        };
      }
      case "getScan": {
        const ctx = await this.contexts.loadScanContext(workspaceId, str("scanId") ?? "", 10);
        const meta = ctx.records[0];
        return { scan: { id: meta?.sourceId, ...(meta?.fields ?? {}) }, limitations: ctx.records.filter((r) => String(r.fields.limitations ?? "")).map((r) => r.fields.limitations) };
      }
      case "getCoverage":
      case "summarizeCoverage": {
        // Coverage is reported from stored scan facts only; where no
        // coverage record exists the honest value is null (unknown) —
        // never a fabricated percentage (P32 §148 pattern).
        const scans = await this.prisma.scan.findMany({ where: { workspaceId }, orderBy: { createdAt: "desc" }, take: 10 });
        return {
          coverage: null,
          note: "no stored coverage aggregate for this workspace — coverage unknown, not assumed",
          scans: (scans as Record<string, unknown>[]).map((s) => ({ id: s.id, status: s.status })),
        };
      }
      case "getSBOM": {
        const subjectId = str("assetId") ?? "";
        const rows = await this.prisma.softwareComponent.findMany({
          where: { OR: [{ imageId: subjectId }, { buildId: subjectId }, { binaryArtifactId: subjectId }, { snapshotId: subjectId }] },
          take: 100,
        });
        if (rows.length === 0) return { components: [], note: "INSUFFICIENT_DATA: no SBOM components stored for this subject" };
        return { components: (rows as Record<string, unknown>[]).map((r) => ({ name: r.name, version: r.version ?? null, ecosystem: r.ecosystem, purl: r.purl })) };
      }
      case "getCveIntel": {
        const cveId = (str("cveId") ?? "").toUpperCase();
        const [rec, epss, kev] = await Promise.all([
          this.prisma.cveRecord.findFirst({ where: { cveId } }),
          this.prisma.epssRecord.findFirst({ where: { cveId }, orderBy: { date: "desc" } }),
          this.prisma.kevRecord.findFirst({ where: { cveId } }),
        ]);
        if (!rec && !epss && !kev) {
          return { intel: null, datasetStatus: "NO_RECORD", note: `no intelligence record for ${cveId} in the local dataset — the copilot must not invent one (§67/§68)` };
        }
        return {
          datasetStatus: "LOCAL_DATASET",
          intel: {
            cve: cveId,
            description: rec?.description ?? null,
            cvssScore: rec?.cvssScore ?? null,
            epssScore: epss?.score ?? null, // null stays null — never 0 (P30 rule)
            kevListed: !!kev,
            kevRequiredAction: kev?.requiredAction ?? null,
          },
        };
      }
      case "getRiskExplanation":
      case "calculateExistingRisk": {
        const f = await this.prisma.finding.findFirst({ where: { id: str("findingId") ?? "", workspaceId } });
        if (!f) throw new NotFoundException("finding not found in this workspace");
        // §70: the stored Risk Engine V3 output is returned verbatim;
        // the AI never recomputes or replaces it.
        return { riskScore: f.riskScore ?? null, riskBand: f.riskBand ?? null, factors: (f.riskExplanation as { factors?: string[] } | null)?.factors ?? [], adjustments: (f.riskExplanation as { adjustments?: unknown[] } | null)?.adjustments ?? [], source: "RISK_ENGINE_V3_STORED" };
      }
      case "getRemediationStatus": {
        const c = await this.prisma.remediationCase.findFirst({ where: { findingId: str("findingId") ?? "", workspaceId } });
        if (!c) return { case: null, note: "no remediation case exists for this finding yet" };
        return { case: { id: c.id, status: c.status, verificationState: c.verificationState, dueAt: c.dueAt ?? null }, sla: { dueAt: c.dueAt ?? null, overdue: c.dueAt ? new Date(c.dueAt) < new Date() : null } };
      }
      case "getIncident": {
        const incident = await this.prisma.securityIncident.findFirst({ where: { id: str("incidentId") ?? "", workspaceId } });
        if (!incident) throw new NotFoundException("incident not found in this workspace");
        const timeline = await this.prisma.incidentTimelineEntry.findMany({ where: { incidentId: incident.id }, orderBy: { createdAt: "asc" }, take: 50 }).catch(() => []);
        return { incident: { id: incident.id, title: incident.title, severity: incident.severity, status: incident.status, detectedAt: incident.detectedAt }, timeline: (timeline as Record<string, unknown>[]).map((t) => ({ at: t.createdAt, summary: t.summary ?? t.entryType ?? "" })) };
      }
      case "compareScans": {
        const [a, b] = await Promise.all([
          this.prisma.finding.findMany({ where: { workspaceId, scanId: str("scanIdA") ?? "" }, take: 2000 }),
          this.prisma.finding.findMany({ where: { workspaceId, scanId: str("scanIdB") ?? "" }, take: 2000 }),
        ]);
        const fp = (r: Record<string, unknown>) => (r.fingerprint as string) ?? (r.id as string);
        const setA = new Map((a as Record<string, unknown>[]).map((r) => [fp(r), r]));
        const setB = new Map((b as Record<string, unknown>[]).map((r) => [fp(r), r]));
        return {
          added: [...setB.keys()].filter((k) => !setA.has(k)).map((k) => ({ id: setB.get(k)!.id, title: setB.get(k)!.title })),
          resolved: [...setA.keys()].filter((k) => !setB.has(k)).map((k) => ({ id: setA.get(k)!.id, title: setA.get(k)!.title })),
          persisting: [...setA.keys()].filter((k) => setB.has(k)).map((k) => ({ id: setA.get(k)!.id, title: setA.get(k)!.title })),
        };
      }
      case "compareVersions": {
        return { changes: [], note: "INSUFFICIENT_DATA: version comparison requires two stored snapshots in this workspace; none were resolved from the supplied references" };
      }
      case "correlateFindings": {
        const ids = Array.isArray(args.findingIds) ? (args.findingIds as string[]) : [];
        const rows = await this.prisma.finding.findMany({ where: { workspaceId, id: { in: ids.slice(0, 50) } } });
        const groups = new Map<string, string[]>();
        for (const r of rows as Record<string, unknown>[]) {
          const key = (r.fingerprint as string) ?? (r.id as string);
          groups.set(key, [...(groups.get(key) ?? []), r.id as string]);
        }
        return { groups: [...groups.entries()].map(([fingerprint, findingIds]) => ({ fingerprint, findingIds })) };
      }
      case "buildAttackPathView": {
        // §71–§73: analytical only. Paths come from stored graph /
        // candidate records; absence is stated, never synthesized.
        const asset = await this.prisma.asset.findFirst({ where: { id: str("assetId") ?? "", workspaceId } });
        if (!asset) throw new NotFoundException("asset not found in this workspace");
        return { paths: [], note: "INSUFFICIENT_DATA: no stored attack-path candidates reference this asset; potential paths are not fabricated (§71)" };
      }
      case "draftScanPlan": {
        const profile = str("profile") ?? AI_SAFE_DEFAULT_PROFILE;
        const cls = classifyScanProfile(profile);
        if (cls === "UNKNOWN") throw new BadRequestException(`profile "${profile}" is not an approved platform profile (§75)`);
        return { plan: { objective: str("objective") ?? "Assess authorized target", profile, profileClass: cls, targetIds: Array.isArray(args.targetIds) ? args.targetIds : [], note: "draft only — validation + approval happen in the planner workflow (§43/§48)" } };
      }
      case "draftVerificationPlan": {
        const f = await this.prisma.finding.findFirst({ where: { id: str("findingId") ?? "", workspaceId } });
        if (!f) throw new NotFoundException("finding not found in this workspace");
        return { plan: { findingId: f.id, kind: "TARGETED_VERIFICATION", note: "minimal targeted verification; execution only via the Prompt 31 workflow (§82/§83)", executed: false } };
      }
      case "draftRemediationPlan": {
        const f = await this.prisma.finding.findFirst({ where: { id: str("findingId") ?? "", workspaceId } });
        if (!f) throw new NotFoundException("finding not found in this workspace");
        return { plan: { findingId: f.id, remediation: f.remediation ?? null, fixedVersion: f.fixedVersion ?? null, note: "draft guidance only — the Prompt 31 lifecycle remains authoritative (§152)" } };
      }
      case "draftInvestigationPlan": {
        const incident = await this.prisma.securityIncident.findFirst({ where: { id: str("incidentId") ?? "", workspaceId } });
        if (!incident) throw new NotFoundException("incident not found in this workspace");
        return { plan: { incidentId: incident.id, checks: ["review linked alerts and timeline", "correlate affected assets and findings", "confirm containment state with the incident commander"], note: "analyst checks only — no automated response action (§86)" } };
      }
      default: {
        // SAFE_ACTION / RESTRICTED_ACTION (§33/§34): record a governed
        // proposal for the owning workflow. Nothing is performed here.
        const actionType = PROPOSAL_ACTION_BY_TOOL[name];
        if (actionType) {
          const proposal = await this.prisma.aiActionProposal.create({
            data: {
              workspaceId, proposedByUserId: user.id, actionType,
              targetType: str("findingId") ? "FINDING" : str("incidentId") ? "INCIDENT" : str("planId") ? "AI_PLAN" : "WORKSPACE",
              targetId: str("findingId") ?? str("incidentId") ?? str("planId") ?? str("reportId") ?? workspaceId,
              summary: `AI tool ${name} hand-off — proposed via the Prompt 36 gateway; the owning workflow decides and executes.`,
              requiredPermission: "RUN_AI_APPROVED_ACTION", status: "PROPOSED",
              scope: { workspaceId, viaTool: name },
            },
          });
          return { proposalId: proposal.id, handedOffTo: "EXISTING_GOVERNED_WORKFLOW", executed: false };
        }
        throw new BadRequestException(`tool ${name} has no governed implementation`);
      }
    }
  }
}
