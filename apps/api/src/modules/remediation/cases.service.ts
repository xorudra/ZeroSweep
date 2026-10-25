import { BadRequestException, Inject, Injectable } from "@nestjs/common";
import { ACTIVE_REMEDIATION_STATUSES, type RemediationStatus } from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { CaseStateService, type CaseRow } from "./case-state.service";
import { OwnershipService } from "./ownership.service";
import { RemediationSlaService } from "./sla.service";
import { requireRemediationPermission } from "./permissions";

export interface CaseFilters {
  status?: string; ownerId?: string; teamId?: string; priority?: string;
  severity?: string; kev?: boolean; slaState?: string; assetId?: string;
  repositoryId?: string; cve?: string; cwe?: string; verificationState?: string;
  patchAvailable?: boolean; search?: string;
  page?: number; pageSize?: number;
}

/**
 * Remediation cases (Prompt 31 §3/§4/§103–§105). One ACTIVE case per
 * canonical finding — creating a second returns the existing case
 * (idempotent ensure). Case creation resolves ownership (§14) and, when
 * a policy resolves, assigns the SLA (§23) — but never invents a due
 * date when no policy matches.
 */
@Injectable()
export class RemediationCasesService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly state: CaseStateService,
    private readonly ownership: OwnershipService,
    private readonly sla: RemediationSlaService,
  ) {}

  /** Ensure (create if needed) the active case for a finding. */
  async ensureCase(user: RequestUser, workspaceId: string, findingId: string, now = new Date()) {
    const finding = await this.state.getFinding(workspaceId, findingId);
    if (finding.duplicateOfId) {
      throw new BadRequestException("duplicate findings are observations of a canonical finding — open the case on the canonical finding (§13)");
    }
    const existing = await this.prisma.remediationCase.findFirst({
      where: { workspaceId, findingId, status: { in: ACTIVE_REMEDIATION_STATUSES } },
      orderBy: { createdAt: "desc" },
    });
    if (existing) return { case: existing as CaseRow, created: false };
    const resolution = await this.ownership.resolveForFinding(workspaceId, finding);
    const kase = await this.prisma.remediationCase.create({
      data: {
        organizationId: user.organizationId, workspaceId, findingId,
        status: "NEW", priority: finding.priority ?? null,
        ownerType: resolution.ownerId || resolution.teamId ? resolution.ownerType : null,
        ownerId: resolution.ownerId ?? null, teamId: resolution.teamId ?? null,
        ownershipConfidence: resolution.confidence,
        verificationState: "NOT_REQUESTED", createdBy: user.id,
      },
    }) as CaseRow;
    await this.prisma.remediationStatusHistory.create({
      data: { caseId: kase.id, workspaceId, fromStatus: null, toStatus: "NEW", actorId: user.id, reason: "case created", evidence: { ownershipSource: resolution.source } as never },
    });
    await this.state.emit(user, workspaceId, kase, "REMEDIATION_CASE_CREATED", { ownershipConfidence: resolution.confidence });
    if (resolution.ownerId || resolution.teamId) {
      await this.prisma.remediationAssignment.create({
        data: {
          caseId: kase.id, workspaceId, ownerType: resolution.ownerType,
          ownerId: resolution.ownerId ?? null, teamId: resolution.teamId ?? null,
          confidence: resolution.confidence, assignedBy: user.id,
          reason: "ownership resolution at case creation", source: resolution.source,
        },
      });
    }
    // SLA assignment is best-effort at creation: no matching policy is a
    // configuration gap to surface on the case, never a fabricated date.
    let slaAssigned = false;
    try {
      await this.sla.assignSla(user, workspaceId, kase.id, now);
      slaAssigned = true;
    } catch {
      slaAssigned = false;
    }
    const fresh = await this.state.getCase(workspaceId, kase.id);
    return { case: fresh, created: true, slaAssigned };
  }

  view(kase: CaseRow, extras: Record<string, unknown> = {}) {
    return {
      id: kase.id, findingId: kase.findingId, workspaceId: kase.workspaceId,
      status: kase.status, priority: kase.priority,
      ownerType: kase.ownerType, ownerId: kase.ownerId, teamId: kase.teamId,
      ownershipConfidence: kase.ownershipConfidence,
      slaPolicyId: kase.slaPolicyId, dueAt: kase.dueAt,
      remediationPlanId: kase.remediationPlanId,
      verificationState: kase.verificationState,
      regressionCount: kase.regressionCount, lastRegressionAt: kase.lastRegressionAt,
      verifiedFixedAt: kase.verifiedFixedAt, closedAt: kase.closedAt,
      createdAt: kase.createdAt, updatedAt: kase.updatedAt,
      ...extras,
    };
  }

  /** The remediation queue (§104) with the spec's filter set. */
  async listQueue(workspaceId: string, filters: CaseFilters) {
    const where: Record<string, unknown> = { workspaceId };
    if (filters.status) where.status = filters.status;
    if (filters.ownerId) where.ownerId = filters.ownerId;
    if (filters.teamId) where.teamId = filters.teamId;
    if (filters.priority) where.priority = filters.priority;
    if (filters.verificationState) where.verificationState = filters.verificationState;
    const rows = (await this.prisma.remediationCase.findMany({ where: where as never, take: 5000, orderBy: { createdAt: "desc" } })) as CaseRow[];
    const findings = new Map<string, Awaited<ReturnType<PrismaClientLike["finding"]["findFirst"]>>>();
    for (const kase of rows) {
      if (!findings.has(kase.findingId)) {
        findings.set(kase.findingId, await this.prisma.finding.findFirst({ where: { id: kase.findingId, workspaceId } }));
      }
    }
    let items = rows.map((kase) => {
      const finding = findings.get(kase.findingId);
      return { kase, finding };
    });
    if (filters.severity) items = items.filter((x) => x.finding?.severity === filters.severity);
    if (filters.kev !== undefined) items = items.filter((x) => (x.finding?.kevListed ?? false) === filters.kev);
    if (filters.cve) items = items.filter((x) => x.finding?.cve?.toUpperCase() === filters.cve!.toUpperCase());
    if (filters.cwe) items = items.filter((x) => x.finding?.cwe?.toUpperCase() === filters.cwe!.toUpperCase());
    if (filters.assetId) items = items.filter((x) => x.finding?.assetId === filters.assetId);
    if (filters.repositoryId) items = items.filter((x) => x.finding?.repositoryId === filters.repositoryId);
    if (filters.patchAvailable !== undefined) {
      items = items.filter((x) => (x.finding?.fixedVersion != null) === filters.patchAvailable);
    }
    if (filters.search) {
      const q = filters.search.toLowerCase();
      items = items.filter((x) => (x.finding?.title ?? "").toLowerCase().includes(q));
    }
    // SLA urgency first: earliest due date, then priority weight.
    const weight = (p: string | null) => ({ P0: 0, P1: 1, P2: 2, P3: 3, P4: 4 }[p ?? "P4"] ?? 5);
    items.sort((a, b) => {
      const ad = a.kase.dueAt?.getTime() ?? Number.MAX_SAFE_INTEGER;
      const bd = b.kase.dueAt?.getTime() ?? Number.MAX_SAFE_INTEGER;
      if (ad !== bd) return ad - bd;
      return weight(a.kase.priority) - weight(b.kase.priority);
    });
    const page = filters.page ?? 1;
    const pageSize = Math.min(filters.pageSize ?? 50, 200);
    const total = items.length;
    return {
      items: items.slice((page - 1) * pageSize, page * pageSize).map(({ kase, finding }) =>
        this.view(kase, {
          finding: finding ? {
            id: finding.id, title: finding.title, severity: finding.severity,
            cve: finding.cve, cwe: finding.cwe, kevListed: finding.kevListed,
            lifecycleStatus: finding.lifecycleStatus, fixedVersion: finding.fixedVersion,
            host: finding.host, assetId: finding.assetId, repositoryId: finding.repositoryId,
          } : null,
        })),
      total, page, pageSize,
    };
  }

  /** Case detail (§105): the case plus every tab's data source. */
  async getCaseDetail(user: RequestUser, workspaceId: string, caseId: string) {
    requireRemediationPermission(user, "VIEW_REMEDIATION");
    const kase = await this.state.getCase(workspaceId, caseId);
    const finding = await this.state.getFinding(workspaceId, kase.findingId);
    const [history, triages, assignments, plans, workItems, claims, jobs, exceptions, snapshot, comments] = await Promise.all([
      this.prisma.remediationStatusHistory.findMany({ where: { caseId }, orderBy: { createdAt: "asc" } }),
      this.prisma.remediationTriage.findMany({ where: { caseId }, orderBy: { createdAt: "desc" } }),
      this.prisma.remediationAssignment.findMany({ where: { caseId }, orderBy: { createdAt: "desc" } }),
      this.prisma.remediationPlan.findMany({ where: { caseId }, orderBy: { createdAt: "desc" } }),
      this.prisma.remediationWorkItem.findMany({ where: { caseId }, orderBy: { createdAt: "desc" } }),
      this.prisma.remediationFixClaim.findMany({ where: { caseId }, orderBy: { createdAt: "desc" } }),
      this.prisma.remediationVerificationJob.findMany({ where: { caseId }, orderBy: { createdAt: "desc" } }),
      this.prisma.remediationException.findMany({ where: { caseId }, orderBy: { createdAt: "desc" } }),
      this.sla.snapshotFor(caseId),
      this.prisma.findingComment.findMany({ where: { findingId: kase.findingId }, orderBy: { createdAt: "asc" } }),
    ]);
    return {
      case: this.view(kase),
      finding: {
        id: finding.id, title: finding.title, description: finding.description,
        severity: finding.severity, priority: finding.priority, cve: finding.cve, cwe: finding.cwe,
        cvssScore: finding.cvssScore, epssScore: finding.epssScore, kevListed: finding.kevListed,
        riskScore: finding.riskScore, riskBand: finding.riskBand, riskExplanation: finding.riskExplanation,
        lifecycleStatus: finding.lifecycleStatus, status: finding.status,
        host: finding.host, endpoint: finding.endpoint, assetId: finding.assetId,
        repositoryId: finding.repositoryId, componentPurl: finding.componentPurl,
        fixedVersion: finding.fixedVersion, fingerprint: finding.fingerprint,
      },
      sla: snapshot,
      timeline: history, triage: triages, assignments, plans, workItems,
      fixClaims: claims, verificationJobs: jobs, exceptions, comments,
    };
  }

  /** Generic guarded status move (PATCH §118). Special targets route
   *  to their engines — this endpoint refuses them so no caller can
   *  bypass verification/closure/claim/exception rules (§157). */
  async transition(user: RequestUser, workspaceId: string, caseId: string, input: { to: RemediationStatus; reason?: string }) {
    requireRemediationPermission(user, "TRIAGE_FINDINGS");
    const guarded: RemediationStatus[] = ["VERIFIED_FIXED", "FIX_CLAIMED", "ACCEPTED_RISK", "FALSE_POSITIVE"];
    if (guarded.includes(input.to)) {
      throw new BadRequestException(`${input.to} is reachable only through its governed workflow (§157)`);
    }
    if (input.to === "CLOSED") {
      throw new BadRequestException("closure goes through the closure engine — POST /remediation/:id/close (§68)");
    }
    const kase = await this.state.getCase(workspaceId, caseId);
    const updated = await this.state.transition(user, workspaceId, kase, { to: input.to, reason: input.reason });
    return this.view(updated);
  }

  /** Dashboard counters (§103) — computed from live case rows. */
  async dashboard(workspaceId: string, now = new Date()) {
    const rows = (await this.prisma.remediationCase.findMany({ where: { workspaceId }, take: 10000 })) as CaseRow[];
    const count = (pred: (k: CaseRow) => boolean) => rows.filter(pred).length;
    const active = (k: CaseRow) => (ACTIVE_REMEDIATION_STATUSES as string[]).includes(k.status);
    return {
      openBacklog: count((k) => active(k)),
      p0: count((k) => active(k) && k.priority === "P0"),
      p1: count((k) => active(k) && k.priority === "P1"),
      dueSoon: count((k) => active(k) && k.dueAt != null && k.dueAt.getTime() >= now.getTime() && k.dueAt.getTime() - now.getTime() <= 48 * 3600 * 1000),
      overdue: count((k) => active(k) && k.dueAt != null && k.dueAt.getTime() < now.getTime()),
      fixClaimed: count((k) => k.status === "FIX_CLAIMED"),
      verificationPending: count((k) => k.status === "VERIFICATION_PENDING" || k.status === "VERIFICATION_RUNNING"),
      verifiedFixed: count((k) => k.status === "VERIFIED_FIXED"),
      closed: count((k) => k.status === "CLOSED"),
      regressions: count((k) => k.regressionCount > 0),
      totalRegressions: rows.reduce((a, k) => a + k.regressionCount, 0),
      exceptions: count((k) => k.status === "ACCEPTED_RISK" || k.status === "DEFERRED"),
      asOf: now,
    };
  }
}
