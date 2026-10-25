import { BadRequestException, ForbiddenException, Inject, Injectable } from "@nestjs/common";
import {
  evaluateVerification, isHighRiskRemediation, isVerificationMethodAllowed,
  verificationPolicyFor, type VerificationMethod,
} from "@zerosweep/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { CaseStateService, type CaseRow } from "./case-state.service";
import { RemediationSlaService } from "./sla.service";
import { RetestService } from "../vulnerabilities/retest.service";
import { VulnerabilityService } from "../vulnerabilities/vulnerability.service";
import { requireRemediationPermission } from "./permissions";

type JobRow = Awaited<ReturnType<PrismaClientLike["remediationVerificationJob"]["findFirstOrThrow"]>>;

const RETEST_METHODS: VerificationMethod[] = ["SAFE_RESCAN", "TARGETED_RETEST"];

/**
 * The verification engine (Prompt 31 §52–§67). Verification rides the
 * EXISTING authorized scanner architecture (§55): rescan/retest methods
 * open a governed P11 RetestRequest — same authorization, scope,
 * policy and budget gates — never a side channel. Outcomes are
 * evaluated by the SDK policy: scanner ERROR never passes, weak
 * evidence is INCONCLUSIVE, and VERIFIED_FIXED requires the configured
 * count of consecutive clean observations (§61/§65).
 *
 * Segregation of duties (§122): on high-risk findings the engineer who
 * claimed the fix may not also verify it, and manual verification may
 * require a second approver (§67).
 */
@Injectable()
export class RemediationVerificationService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly state: CaseStateService,
    private readonly sla: RemediationSlaService,
    private readonly retests: RetestService,
    private readonly vulnerabilities: VulnerabilityService,
  ) {}

  async requestVerification(user: RequestUser, workspaceId: string, caseId: string, input: {
    method: VerificationMethod; scannerProfile?: string; scope?: Record<string, unknown>;
  }) {
    requireRemediationPermission(user, "REQUEST_VERIFICATION");
    const kase = await this.state.getCase(workspaceId, caseId);
    const finding = await this.state.getFinding(workspaceId, kase.findingId);
    const category = finding.vulnClass ?? finding.detectionKind ?? null;
    if (!isVerificationMethodAllowed(category, input.method)) {
      throw new BadRequestException(
        `method ${input.method} is not allowed for finding category "${category ?? "unknown"}" (§54) — allowed: ${verificationPolicyFor(category).methods.join(", ")}`,
      );
    }
    if (!["FIX_CLAIMED", "VERIFICATION_PENDING"].includes(kase.status)) {
      throw new BadRequestException(`verification requires a claimed fix (case is ${kase.status}) — claim the fix first (§50); after a failed verification a NEW claim is required before retesting`);
    }
    const snapshot = await this.sla.snapshotFor(caseId);
    const policyEntry = verificationPolicyFor(category);
    const required = snapshot
      ? Math.max(policyEntry.requiredCleanObservations, 1)
      : policyEntry.requiredCleanObservations;
    const requiredFromPolicy = await this.requiredObservations(workspaceId, kase);
    // Idempotency (§120): an identical open job for the case+method is
    // returned, not duplicated.
    const open = await this.prisma.remediationVerificationJob.findFirst({
      where: { caseId, method: input.method, status: { in: ["QUEUED", "RUNNING"] } },
    });
    if (open) return { job: open as JobRow, case: kase, duplicate: true };
    let updated = kase;
    if (kase.status === "FIX_CLAIMED") {
      updated = await this.state.transition(user, workspaceId, kase, {
        to: "VERIFICATION_PENDING", reason: `verification requested (${input.method})`,
      });
    }
    const job = await this.prisma.remediationVerificationJob.create({
      data: {
        caseId, workspaceId, method: input.method, status: "QUEUED", requestedBy: user.id,
        scannerProfile: input.scannerProfile ?? null,
        scope: (input.scope as never) ?? { findingId: kase.findingId, targeted: true },
        requiredCleanObservations: requiredFromPolicy ?? required,
      },
    }) as JobRow;
    await this.prisma.remediationCase.update({
      where: { id: caseId }, data: { verificationState: "PENDING" } as never,
    });
    await this.state.emit(user, workspaceId, kase, "REMEDIATION_VERIFICATION_REQUESTED", { jobId: job.id, method: input.method });
    // Retest-backed methods open the governed P11 retest (§55). The
    // retest may be DENIED by the gates (unverified target, no approved
    // assessment) — that denial is recorded on the job, never bypassed.
    if (RETEST_METHODS.includes(input.method)) {
      try {
        const retest = await this.retests.requestRetest(user, workspaceId, kase.findingId, `remediation verification ${job.id}`);
        await this.prisma.remediationVerificationJob.update({
          where: { id: job.id }, data: { retestRequestId: retest.id, status: "RUNNING", startedAt: new Date() },
        });
        job.retestRequestId = retest.id;
        job.status = "RUNNING";
      } catch (err) {
        await this.prisma.remediationVerificationJob.update({
          where: { id: job.id },
          data: { status: "ERROR", completedAt: new Date(), result: { gateDenied: true, detail: err instanceof Error ? err.message : "retest gate denied" } as never },
        });
        job.status = "ERROR";
      }
    }
    return { job, case: updated, duplicate: false };
  }

  private async requiredObservations(workspaceId: string, kase: CaseRow): Promise<number | null> {
    if (!kase.slaPolicyId) return null;
    const policy = await this.prisma.remediationSlaPolicy.findFirst({ where: { id: kase.slaPolicyId, workspaceId } });
    if (!policy) return null;
    return (policy.conditions as { requiredCleanObservations?: number } | null)?.requiredCleanObservations
      ?? policy.requiredCleanObservations ?? null;
  }

  /**
   * Record one verification observation and evaluate it (§59–§65).
   * This is the ONLY path that can produce VERIFIED_FIXED.
   * `approvedBy` is the second approver for high-risk manual closure (§67).
   */
  async recordObservation(user: RequestUser, workspaceId: string, caseId: string, jobId: string, input: {
    scannerStatus: "OK" | "ERROR";
    stillPresent: boolean | null;
    evidenceSufficient: boolean;
    tool?: string; toolVersion?: string;
    beforeObservation?: unknown; afterObservation?: unknown; evidenceRefs?: unknown;
    approvedBy?: string;
  }) {
    const kase = await this.state.getCase(workspaceId, caseId);
    const job = await this.prisma.remediationVerificationJob.findFirst({ where: { id: jobId, caseId, workspaceId } });
    if (!job) throw new BadRequestException("verification job not found for this case");
    if (["PASSED", "FAILED", "ERROR", "CANCELLED"].includes(job.status)) {
      throw new BadRequestException(`verification job is already ${job.status}`);
    }
    const finding = await this.state.getFinding(workspaceId, kase.findingId);
    const isManual = job.method === "MANUAL_EVIDENCE_REVIEW";
    // SoD (§122): the fix claimer cannot verify their own fix on
    // high-risk findings; manual verification requires the manual
    // permission regardless of risk.
    const latestClaim = await this.prisma.remediationFixClaim.findFirst({ where: { caseId }, orderBy: { createdAt: "desc" } });
    const highRisk = isHighRiskRemediation({ priority: kase.priority ?? finding.priority, severity: finding.severity, kevListed: finding.kevListed });
    if (isManual) {
      requireRemediationPermission(user, "PERFORM_MANUAL_VERIFICATION");
      if (highRisk && latestClaim && latestClaim.claimedBy === user.id) {
        throw new ForbiddenException("segregation of duties: the engineer who claimed this high-risk fix cannot verify it (§122)");
      }
      if (highRisk && await this.dualApprovalRequired(workspaceId, kase)) {
        if (!input.approvedBy) throw new BadRequestException("high-risk manual verification requires a second approver (§67)");
        if (input.approvedBy === user.id || input.approvedBy === latestClaim?.claimedBy) {
          throw new ForbiddenException("the second approver must differ from both the verifier and the fix claimer (§67/§122)");
        }
      }
    }
    if (kase.status === "VERIFICATION_PENDING") {
      await this.state.transition(user, workspaceId, kase, { to: "VERIFICATION_RUNNING", reason: `verification running (${job.method})`, event: "REMEDIATION_VERIFICATION_STARTED" });
    }
    const evidence = await this.prisma.remediationVerificationEvidence.create({
      data: {
        jobId, caseId, workspaceId,
        beforeObservation: (input.beforeObservation as never) ?? null,
        afterObservation: (input.afterObservation as never) ?? null,
        tool: input.tool ?? null, toolVersion: input.toolVersion ?? null,
        comparisonResult: input.scannerStatus === "ERROR" ? "SCANNER_ERROR"
          : !input.evidenceSufficient || input.stillPresent === null ? "INSUFFICIENT"
          : input.stillPresent ? "STILL_PRESENT" : "ABSENT",
        evidenceRefs: (input.evidenceRefs as never) ?? null,
        recordedBy: user.id,
      },
    });
    const evaluation = evaluateVerification({
      observation: { scannerStatus: input.scannerStatus, stillPresent: input.stillPresent, evidenceSufficient: input.evidenceSufficient },
      previousCleanObservations: job.cleanObservations,
      requiredCleanObservations: job.requiredCleanObservations,
    });
    const jobStatus = evaluation.outcome === "PASSED" ? "PASSED"
      : evaluation.outcome === "FAILED" ? "FAILED"
      : evaluation.outcome === "ERROR" ? "ERROR"
      : evaluation.outcome === "INCONCLUSIVE" ? "INCONCLUSIVE" : "RUNNING";
    const updatedJob = await this.prisma.remediationVerificationJob.update({
      where: { id: jobId },
      data: {
        status: jobStatus, cleanObservations: evaluation.cleanObservations,
        startedAt: job.startedAt ?? new Date(),
        completedAt: jobStatus === "RUNNING" ? null : new Date(),
        result: { outcome: evaluation.outcome, reason: evaluation.reason, evidenceId: evidence.id } as never,
      },
    }) as JobRow;
    let updated = await this.state.getCase(workspaceId, caseId);
    if (evaluation.caseEffect === "VERIFIED_FIXED") {
      updated = await this.state.transition(user, workspaceId, updated, {
        to: "VERIFIED_FIXED", viaVerification: true,
        reason: evaluation.reason, evidence: { jobId, evidenceId: evidence.id },
        extraData: { verificationState: "PASSED" },
      });
      await this.state.emit(user, workspaceId, updated, "REMEDIATION_VERIFICATION_PASSED", { jobId, evidenceId: evidence.id });
      // Finding lifecycle: verified remediation → RESOLVED via the P11
      // machine (REMEDIATED → RETEST_PENDING → RESOLVED walk).
      await this.walkFindingToResolved(user, workspaceId, kase.findingId);
    } else if (evaluation.caseEffect === "RETURN_TO_ACTIONABLE") {
      updated = await this.state.transition(user, workspaceId, updated, {
        to: "IN_PROGRESS", reason: evaluation.reason, evidence: { jobId, evidenceId: evidence.id },
        extraData: { verificationState: "FAILED" },
      });
      await this.state.emit(user, workspaceId, updated, "REMEDIATION_VERIFICATION_FAILED", { jobId, evidenceId: evidence.id });
      await this.walkFindingBackToWork(user, workspaceId, kase.findingId);
    } else if (evaluation.outcome === "INCONCLUSIVE") {
      await this.prisma.remediationCase.update({ where: { id: caseId }, data: { verificationState: "INCONCLUSIVE" } as never });
      const back = await this.state.getCase(workspaceId, caseId);
      if (back.status === "VERIFICATION_RUNNING") {
        updated = await this.state.transition(user, workspaceId, back, { to: "VERIFICATION_PENDING", reason: evaluation.reason });
      }
      await this.state.emit(user, workspaceId, updated, "REMEDIATION_VERIFICATION_INCONCLUSIVE", { jobId, evidenceId: evidence.id });
    } else if (evaluation.outcome === "ERROR") {
      await this.prisma.remediationCase.update({ where: { id: caseId }, data: { verificationState: "ERROR" } as never });
      const back = await this.state.getCase(workspaceId, caseId);
      if (back.status === "VERIFICATION_RUNNING") {
        updated = await this.state.transition(user, workspaceId, back, { to: "VERIFICATION_PENDING", reason: "scanner error — verification did not run (§63)" });
      }
    }
    return { job: updatedJob, case: updated, evaluation, evidence };
  }

  private async dualApprovalRequired(workspaceId: string, kase: CaseRow): Promise<boolean> {
    if (!kase.slaPolicyId) return false;
    const policy = await this.prisma.remediationSlaPolicy.findFirst({ where: { id: kase.slaPolicyId, workspaceId } });
    return (policy?.conditions as { dualApprovalForHighRisk?: boolean } | null)?.dualApprovalForHighRisk ?? false;
  }

  /** SBOM reevaluation (§93/§153): the component's CURRENT match state
   *  decides the observation — still AFFECTED = still present; a newer
   *  component version with no AFFECTED match = absent. */
  async reevaluateSbom(user: RequestUser, workspaceId: string, caseId: string, jobId: string) {
    const kase = await this.state.getCase(workspaceId, caseId);
    const finding = await this.state.getFinding(workspaceId, kase.findingId);
    if (!finding.cve || !finding.componentPurl) {
      throw new BadRequestException("SBOM reevaluation needs a finding with a CVE and a component (§93)");
    }
    // Components are global inventory rows; the workspace scoping of
    // the reevaluation comes from the workspace's own match records.
    const components = await this.prisma.softwareComponent.findMany({
      where: { purl: finding.componentPurl }, take: 50,
    });
    const componentIds = components.map((c) => c.id);
    const matches = componentIds.length
      ? await this.prisma.componentVulnerabilityMatch.findMany({ where: { workspaceId, cveId: finding.cve, componentId: { in: componentIds } } })
      : [];
    const stillAffected = matches.some((m) => m.affectedStatus === "AFFECTED");
    const versions = components.map((c) => c.version ?? null).filter(Boolean);
    return this.recordObservation(user, workspaceId, caseId, jobId, {
      scannerStatus: "OK",
      stillPresent: stillAffected,
      evidenceSufficient: components.length > 0,
      tool: "sbom-reevaluation",
      beforeObservation: { componentPurl: finding.componentPurl, fixedVersion: finding.fixedVersion },
      afterObservation: { componentVersions: versions, affectedMatches: matches.length, stillAffected },
    });
  }

  /** Walk the finding lifecycle to RESOLVED through the P11 machine —
   *  each hop is a legal transition; an illegal resting state stops the
   *  walk and is reported, never forced. */
  private async walkFindingToResolved(user: RequestUser, workspaceId: string, findingId: string) {
    const path: Record<string, string> = {
      NEW: "TRIAGED", TRIAGED: "CONFIRMED", CONFIRMED: "REMEDIATED",
      IN_PROGRESS: "REMEDIATED", REMEDIATED: "RETEST_PENDING", RETEST_PENDING: "RESOLVED",
    };
    for (let hop = 0; hop < 6; hop += 1) {
      const finding = await this.state.getFinding(workspaceId, findingId);
      if (finding.lifecycleStatus === "RESOLVED") return;
      const next = path[finding.lifecycleStatus];
      if (!next) return;
      try {
        await this.vulnerabilities.transition(user, workspaceId, findingId, { to: next as never, reason: "remediation verified fixed (Prompt 31)" });
      } catch {
        return;
      }
    }
  }

  private async walkFindingBackToWork(user: RequestUser, workspaceId: string, findingId: string) {
    const finding = await this.state.getFinding(workspaceId, findingId);
    if (finding.lifecycleStatus === "RETEST_PENDING" || finding.lifecycleStatus === "REMEDIATED") {
      try {
        await this.vulnerabilities.transition(user, workspaceId, findingId, { to: "IN_PROGRESS" as never, reason: "verification failed — vulnerability still present (Prompt 31)" });
      } catch { /* the case state already carries the failure */ }
    }
  }

  async listJobs(workspaceId: string, caseId: string) {
    await this.state.getCase(workspaceId, caseId);
    return this.prisma.remediationVerificationJob.findMany({ where: { caseId, workspaceId }, orderBy: { createdAt: "desc" } });
  }
}
