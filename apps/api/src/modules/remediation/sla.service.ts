import { BadRequestException, ForbiddenException, Inject, Injectable } from "@nestjs/common";
import {
  SLA_PAUSE_REASONS, deriveSlaState, evaluateSlaRecalculation, resolveRemediationSla,
  type RemediationSlaPolicyView, type SlaPauseReason,
} from "@dsrclone/security-sdk";
import { PRISMA, type PrismaClientLike } from "../../prisma/prisma.module";
import type { RequestUser } from "../../common/decorators/auth.decorators";
import { CaseStateService, type CaseRow } from "./case-state.service";
import { NotificationRouterService } from "../continuous-security/notifications/notification-router.service";
import { requireRemediationPermission } from "./permissions";

type PolicyRow = Awaited<ReturnType<PrismaClientLike["remediationSlaPolicy"]["findFirstOrThrow"]>>;
type SnapshotRow = Awaited<ReturnType<PrismaClientLike["remediationSlaSnapshot"]["findFirstOrThrow"]>>;

const TERMINAL_CASE_STATUSES = ["CLOSED", "VERIFIED_FIXED", "FALSE_POSITIVE"];

/**
 * SLA policies, snapshots, pauses and the evaluation tick
 * (Prompt 31 §21–§31). Assignment snapshots the resolution (policy id,
 * version, target, inputs) onto the case (§24). The tick derives state
 * from stored timestamps only — warning/at-risk/breach transitions emit
 * the §30 events and route notifications through the P22 router (§31);
 * external channels stay RECORDED_NOT_DELIVERED/NOT_CONFIGURED there,
 * never fake-sent.
 */
@Injectable()
export class RemediationSlaService {
  constructor(
    @Inject(PRISMA) private readonly prisma: PrismaClientLike,
    private readonly cases: CaseStateService,
    private readonly notifications: NotificationRouterService,
  ) {}

  private toView(row: PolicyRow): RemediationSlaPolicyView {
    return {
      id: row.id, name: row.name, version: row.version, isDefault: row.isDefault, active: row.active,
      rules: (row.rules as Record<string, number>) ?? {},
      conditions: (row.conditions as RemediationSlaPolicyView["conditions"]) ?? null,
      warningThresholds: (row.warningThresholds as RemediationSlaPolicyView["warningThresholds"]) ?? null,
      escalation: (row.escalation as RemediationSlaPolicyView["escalation"]) ?? null,
      verificationRequired: row.verificationRequired,
      requiredCleanObservations: row.requiredCleanObservations,
    };
  }

  async listPolicies(workspaceId: string) {
    const rows = await this.prisma.remediationSlaPolicy.findMany({ where: { workspaceId }, orderBy: { createdAt: "asc" } });
    return rows.map((r) => this.toView(r as PolicyRow));
  }

  async createPolicy(user: RequestUser, workspaceId: string, input: {
    name: string; rules: Record<string, number>; isDefault?: boolean;
    conditions?: RemediationSlaPolicyView["conditions"];
    warningThresholds?: RemediationSlaPolicyView["warningThresholds"];
    escalation?: RemediationSlaPolicyView["escalation"];
    verificationRequired?: boolean; requiredCleanObservations?: number;
  }) {
    requireRemediationPermission(user, "MANAGE_REMEDIATION_SLA");
    if (!input.name?.trim()) throw new BadRequestException("policy name is required");
    if (input.isDefault) {
      await this.prisma.remediationSlaPolicy.updateMany({ where: { workspaceId, isDefault: true }, data: { isDefault: false } });
    }
    const row = await this.prisma.remediationSlaPolicy.create({
      data: {
        workspaceId, name: input.name, rules: input.rules as never, isDefault: input.isDefault ?? false,
        createdBy: user.id, version: 1,
        conditions: (input.conditions as never) ?? null,
        warningThresholds: (input.warningThresholds as never) ?? null,
        escalation: (input.escalation as never) ?? null,
        verificationRequired: input.verificationRequired ?? true,
        requiredCleanObservations: input.requiredCleanObservations ?? 1,
      },
    });
    return this.toView(row as PolicyRow);
  }

  /** A policy edit is a new VERSION (§24) — snapshots keep pointing at
   *  the version they were resolved under. */
  async updatePolicy(user: RequestUser, workspaceId: string, policyId: string, input: Partial<{
    rules: Record<string, number>; conditions: RemediationSlaPolicyView["conditions"];
    warningThresholds: RemediationSlaPolicyView["warningThresholds"]; active: boolean;
    verificationRequired: boolean; requiredCleanObservations: number;
  }>) {
    requireRemediationPermission(user, "MANAGE_REMEDIATION_SLA");
    const row = await this.prisma.remediationSlaPolicy.findFirst({ where: { id: policyId, workspaceId } });
    if (!row) throw new BadRequestException("SLA policy not found in this workspace");
    const updated = await this.prisma.remediationSlaPolicy.update({
      where: { id: policyId },
      data: {
        ...(input.rules ? { rules: input.rules as never } : {}),
        ...(input.conditions !== undefined ? { conditions: input.conditions as never } : {}),
        ...(input.warningThresholds !== undefined ? { warningThresholds: input.warningThresholds as never } : {}),
        ...(input.active !== undefined ? { active: input.active } : {}),
        ...(input.verificationRequired !== undefined ? { verificationRequired: input.verificationRequired } : {}),
        ...(input.requiredCleanObservations !== undefined ? { requiredCleanObservations: input.requiredCleanObservations } : {}),
        version: row.version + 1,
      },
    });
    return this.toView(updated as PolicyRow);
  }

  async inputsFor(workspaceId: string, kase: CaseRow) {
    const finding = await this.cases.getFinding(workspaceId, kase.findingId);
    let criticality: string | null = null;
    let internetExposed = (finding.tags ?? []).some((t) => t.toLowerCase().includes("internet") || t.toLowerCase().includes("public"));
    if (finding.assetId) {
      const asset = await this.prisma.asset.findFirst({ where: { id: finding.assetId, workspaceId } });
      criticality = (asset as unknown as { criticality?: string } | null)?.criticality ?? null;
      const exposure = (asset as unknown as { exposure?: string } | null)?.exposure;
      if (exposure && /public|internet/i.test(exposure)) internetExposed = true;
    }
    return {
      finding,
      inputs: {
        priority: kase.priority ?? finding.priority ?? null,
        severity: finding.severity,
        kevListed: finding.kevListed,
        internetExposed,
        assetCriticality: criticality,
        category: finding.vulnClass ?? finding.detectionKind ?? null,
      },
    };
  }

  /** Assign (or re-assign) the SLA for a case: resolve → snapshot →
   *  mirror dueAt/policy onto the case (§23/§24). */
  async assignSla(user: RequestUser, workspaceId: string, caseId: string, now = new Date()) {
    requireRemediationPermission(user, "MANAGE_REMEDIATION_SLA");
    const kase = await this.cases.getCase(workspaceId, caseId);
    const policies = (await this.prisma.remediationSlaPolicy.findMany({ where: { workspaceId } })).map((r) => this.toView(r as PolicyRow));
    const { inputs } = await this.inputsFor(workspaceId, kase);
    const resolution = resolveRemediationSla(policies, inputs);
    if (!resolution) {
      throw new BadRequestException("no configured SLA policy yields a duration for this case — configure a RemediationSlaPolicy (§21); no due date is invented");
    }
    const dueAt = new Date(now.getTime() + resolution.targetHours * 3600 * 1000);
    const existing = await this.prisma.remediationSlaSnapshot.findFirst({ where: { caseId }, orderBy: { createdAt: "desc" } });
    let snapshot: SnapshotRow;
    if (existing && !existing.completedAt) {
      snapshot = await this.prisma.remediationSlaSnapshot.update({
        where: { id: existing.id },
        data: {
          policyId: resolution.policyId, policyVersion: resolution.policyVersion,
          inputs: resolution.inputs as never, targetHours: resolution.targetHours,
          startedAt: now, dueAt, state: "ON_TRACK", lastEvaluatedAt: now,
        },
      }) as SnapshotRow;
    } else {
      snapshot = await this.prisma.remediationSlaSnapshot.create({
        data: {
          caseId, workspaceId, policyId: resolution.policyId, policyVersion: resolution.policyVersion,
          inputs: resolution.inputs as never, targetHours: resolution.targetHours,
          startedAt: now, dueAt, state: "ON_TRACK", lastEvaluatedAt: now,
        },
      }) as SnapshotRow;
    }
    const updated = await this.prisma.remediationCase.update({
      where: { id: caseId }, data: { slaPolicyId: resolution.policyId, dueAt } as never,
    }) as CaseRow;
    await this.prisma.finding.update({ where: { id: kase.findingId }, data: { slaPolicyId: resolution.policyId, dueAt } as never });
    await this.cases.emit(user, workspaceId, kase, "REMEDIATION_SLA_ASSIGNED", {
      policyId: resolution.policyId, policyVersion: resolution.policyVersion,
      targetHours: resolution.targetHours, dueAt: dueAt.toISOString(),
    });
    return { case: updated, snapshot, resolution };
  }

  /** §25: propose/apply a recalculation. Shortening is refused unless
   *  the CURRENT policy version explicitly allows it. */
  async recalculate(user: RequestUser, workspaceId: string, caseId: string, input: { allowShorten?: boolean }, now = new Date()) {
    requireRemediationPermission(user, "MANAGE_REMEDIATION_SLA");
    const kase = await this.cases.getCase(workspaceId, caseId);
    const snapshot = await this.prisma.remediationSlaSnapshot.findFirst({ where: { caseId }, orderBy: { createdAt: "desc" } });
    if (!snapshot || !kase.dueAt) throw new BadRequestException("case has no SLA snapshot to recalculate");
    const policies = (await this.prisma.remediationSlaPolicy.findMany({ where: { workspaceId } })).map((r) => this.toView(r as PolicyRow));
    const { inputs } = await this.inputsFor(workspaceId, kase);
    const resolution = resolveRemediationSla(policies, inputs);
    if (!resolution) throw new BadRequestException("no configured SLA policy resolves for the current inputs");
    const proposedDueAt = new Date(snapshot.startedAt.getTime() + resolution.targetHours * 3600 * 1000 + snapshot.pausedDurationMs);
    const verdict = evaluateSlaRecalculation({ currentDueAt: kase.dueAt, proposedDueAt, allowShorten: input.allowShorten ?? false });
    if (verdict.applied) {
      await this.prisma.remediationSlaSnapshot.update({ where: { id: snapshot.id }, data: { dueAt: verdict.dueAt, targetHours: resolution.targetHours, policyVersion: resolution.policyVersion } });
      await this.prisma.remediationCase.update({ where: { id: caseId }, data: { dueAt: verdict.dueAt } as never });
      await this.prisma.finding.update({ where: { id: kase.findingId }, data: { dueAt: verdict.dueAt } as never });
    }
    return { ...verdict, proposedDueAt, evaluatedAt: now };
  }

  /** §28/§29: pause with a CONFIGURED reason + permission; the pause
   *  row records who/why/when and (for APPROVED_EXCEPTION) the approver. */
  async pauseSla(user: RequestUser, workspaceId: string, caseId: string, input: { reason: string; approvedBy?: string }, now = new Date()) {
    requireRemediationPermission(user, "PAUSE_REMEDIATION_SLA");
    if (!(SLA_PAUSE_REASONS as readonly string[]).includes(input.reason)) {
      throw new BadRequestException(`pause reason must be one of ${SLA_PAUSE_REASONS.join(", ")} (§28)`);
    }
    if (input.reason === "APPROVED_EXCEPTION" && !input.approvedBy) {
      throw new BadRequestException("APPROVED_EXCEPTION pause requires the approver (§29)");
    }
    const kase = await this.cases.getCase(workspaceId, caseId);
    const snapshot = await this.prisma.remediationSlaSnapshot.findFirst({ where: { caseId }, orderBy: { createdAt: "desc" } });
    if (!snapshot) throw new BadRequestException("case has no SLA snapshot");
    if (snapshot.pausedAt) throw new BadRequestException("SLA is already paused");
    if (snapshot.completedAt) throw new BadRequestException("SLA already completed");
    const pause = await this.prisma.remediationSlaPause.create({
      data: {
        snapshotId: snapshot.id, caseId, workspaceId, reason: input.reason as SlaPauseReason,
        startedBy: user.id, approvedBy: input.approvedBy ?? null, startedAt: now,
      },
    });
    await this.prisma.remediationSlaSnapshot.update({ where: { id: snapshot.id }, data: { pausedAt: now, pauseReason: input.reason, state: "PAUSED" } });
    await this.cases.emit(user, workspaceId, kase, "REMEDIATION_SLA_PAUSED", { reason: input.reason, pauseId: pause.id });
    return pause;
  }

  async resumeSla(user: RequestUser, workspaceId: string, caseId: string, now = new Date()) {
    requireRemediationPermission(user, "PAUSE_REMEDIATION_SLA");
    const kase = await this.cases.getCase(workspaceId, caseId);
    const snapshot = await this.prisma.remediationSlaSnapshot.findFirst({ where: { caseId }, orderBy: { createdAt: "desc" } });
    if (!snapshot?.pausedAt) throw new BadRequestException("SLA is not paused");
    const pauseMs = now.getTime() - snapshot.pausedAt.getTime();
    await this.prisma.remediationSlaPause.updateMany({
      where: { snapshotId: snapshot.id, endedAt: null },
      data: { endedAt: now, endedBy: user.id },
    });
    const updated = await this.prisma.remediationSlaSnapshot.update({
      where: { id: snapshot.id },
      data: { pausedAt: null, pauseReason: null, pausedDurationMs: snapshot.pausedDurationMs + pauseMs, state: "ON_TRACK" },
    });
    await this.cases.emit(user, workspaceId, kase, "REMEDIATION_SLA_ASSIGNED", { resumed: true, pausedDurationMs: updated.pausedDurationMs });
    return updated;
  }

  async snapshotFor(caseId: string): Promise<SnapshotRow | null> {
    return (await this.prisma.remediationSlaSnapshot.findFirst({ where: { caseId }, orderBy: { createdAt: "desc" } })) as SnapshotRow | null;
  }

  /**
   * Evaluation tick (§26/§30/§31): derive every open snapshot's state
   * from the clock; on a state CHANGE into WARNING / AT_RISK / BREACHED
   * emit the event + route a notification. Breach also stamps the case
   * history. Completed when the case reaches a terminal state.
   */
  async evaluateWorkspace(user: RequestUser, workspaceId: string, now = new Date()) {
    const snapshots = await this.prisma.remediationSlaSnapshot.findMany({
      where: { workspaceId, completedAt: null }, take: 5000,
    });
    const changes: Array<{ caseId: string; from: string; to: string }> = [];
    for (const snap of snapshots as SnapshotRow[]) {
      const kase = await this.prisma.remediationCase.findFirst({ where: { id: snap.caseId, workspaceId } });
      if (!kase) continue;
      const policy = snap.policyId
        ? await this.prisma.remediationSlaPolicy.findFirst({ where: { id: snap.policyId, workspaceId } })
        : null;
      const derived = deriveSlaState({
        startedAt: snap.startedAt, dueAt: snap.dueAt, pausedDurationMs: snap.pausedDurationMs,
        pausedAt: snap.pausedAt, completedAt: snap.completedAt, state: snap.state as never,
        warningPct: (policy?.warningThresholds as { warningPct?: number } | null)?.warningPct ?? 0.5,
        atRiskPct: (policy?.warningThresholds as { atRiskPct?: number } | null)?.atRiskPct ?? 0.8,
      }, now);
      let nextState = derived.state as string;
      if (TERMINAL_CASE_STATUSES.includes(kase.status)) nextState = "COMPLETED";
      if (nextState === snap.state) {
        await this.prisma.remediationSlaSnapshot.update({ where: { id: snap.id }, data: { lastEvaluatedAt: now } });
        continue;
      }
      await this.prisma.remediationSlaSnapshot.update({
        where: { id: snap.id },
        data: { state: nextState, lastEvaluatedAt: now, ...(nextState === "COMPLETED" ? { completedAt: now } : {}) },
      });
      changes.push({ caseId: snap.caseId, from: snap.state, to: nextState });
      const event = nextState === "WARNING" ? "REMEDIATION_SLA_WARNING"
        : nextState === "AT_RISK" ? "REMEDIATION_SLA_AT_RISK"
        : nextState === "BREACHED" ? "REMEDIATION_SLA_BREACHED" : null;
      if (event) {
        await this.cases.emit(user, workspaceId, kase, event, { from: snap.state, to: nextState, dueAt: snap.dueAt.toISOString() });
        const finding = await this.cases.getFinding(workspaceId, kase.findingId);
        await this.notifications.routeEvent(workspaceId, {
          type: event, workspaceId, findingId: kase.findingId,
          severity: finding.severity, priority: kase.priority ?? finding.priority ?? undefined,
          contentHash: `${snap.id}:${nextState}`,
          title: `Remediation SLA ${nextState.toLowerCase().replace("_", " ")}: ${finding.title}`,
          detail: `case ${kase.id} due ${snap.dueAt.toISOString()}`,
        }, now);
        if (nextState === "BREACHED") {
          await this.prisma.remediationStatusHistory.create({
            data: {
              caseId: kase.id, workspaceId, fromStatus: kase.status, toStatus: kase.status,
              actorId: user.id, reason: "SLA breached", evidence: { slaState: "BREACHED", dueAt: snap.dueAt.toISOString() } as never,
            },
          });
        }
      }
    }
    return { evaluated: snapshots.length, changes };
  }

  /** SLA dashboard aggregate (§106). */
  async dashboard(workspaceId: string, now = new Date()) {
    const snapshots = await this.prisma.remediationSlaSnapshot.findMany({ where: { workspaceId }, take: 5000 });
    const byState: Record<string, number> = { ON_TRACK: 0, WARNING: 0, AT_RISK: 0, BREACHED: 0, PAUSED: 0, COMPLETED: 0 };
    const byTeam: Record<string, { total: number; breached: number }> = {};
    for (const snap of snapshots as SnapshotRow[]) {
      const derived = deriveSlaState({
        startedAt: snap.startedAt, dueAt: snap.dueAt, pausedDurationMs: snap.pausedDurationMs,
        pausedAt: snap.pausedAt, completedAt: snap.completedAt, state: snap.state as never,
        warningPct: 0.5, atRiskPct: 0.8,
      }, now);
      const state = snap.completedAt ? "COMPLETED" : derived.state;
      byState[state] = (byState[state] ?? 0) + 1;
      const kase = await this.prisma.remediationCase.findFirst({ where: { id: snap.caseId, workspaceId } });
      const team = kase?.teamId ?? kase?.ownerId ?? "unassigned";
      byTeam[team] = byTeam[team] ?? { total: 0, breached: 0 };
      byTeam[team].total += 1;
      if (state === "BREACHED") byTeam[team].breached += 1;
    }
    return { byState, byTeam, total: snapshots.length, asOf: now };
  }
}
